use std::error::Error;
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::proxy::Proxy;
use crate::socks5::libs::io::bidirectional_streaming;
use crate::socks5::libs::statics::AuthMethods;

pub fn check_valid_version(version: &u8) -> bool {
    // Check if version is 5
    return 0x05 == *version;
}

pub async fn start_proxy(
    proxy: Arc<Proxy>,
    server_addr: Option<String>,
    server_port: Option<i32>,
) -> Result<(), Box<dyn Error>> {
    let proxy_addr = String::from(format!(
        "{}:{}",
        server_addr.unwrap_or(String::from("0.0.0.0")),
        server_port.unwrap_or(1080)
    ));

    let listener = TcpListener::bind(proxy_addr.clone()).await?;

    println!("Proxys listening on: {}", proxy_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let copy = proxy.clone();
        tokio::spawn(async move {
            handle_connection(copy, socket).await;
        });
    }
}

async fn handle_connection(proxy: Arc<Proxy>, mut socket: TcpStream) {
    let mut buf: [u8; 258] = [0; 258];

    match socket.read(&mut buf).await {
        Ok(n) => {
            if !check_valid_version(&buf[0]) {
                println!("Not socks5 version");
                return;
            }

            // Auth Checking
            let nmethod: u8 = buf[1];

            let methods = &buf[2..(2 + nmethod as usize)];

            // Server has two auth methods
            // UsernamePassword and NoAuth
            // usernamePassword  is most priority
            // check first if usernamePassword is available
            if (methods
                .contains(&AuthMethods::UsernamePassword.to_u8())
                && proxy.check_valid_auth_method(
                    &AuthMethods::UsernamePassword,
                ))
            {
                println!("UsernamePassword");

                // Write
                match socket
                    .write(&[
                        5,                                     // Version
                        AuthMethods::UsernamePassword.to_u8(), // UsernamePassword
                    ])
                    .await
                {
                    Ok(n) => {}
                    Err(e) => {
                        println!("Error sending response");
                        return;
                    }
                }

                // Read UsernamePassword
                let mut buf: [u8; 258] = [0; 258];

                match socket.read(&mut buf).await {
                    Ok(n) => {
                        println!("UsernamePassword: {:?}", buf);

                        let username_length = buf[1];
                        let password_length =
                            buf[2 + username_length as usize];

                        let username =
                            &buf[2..(2 + username_length as usize)];
                        let password = &buf[(3 + username_length
                            as usize)
                            ..(3 + username_length as usize
                                + password_length as usize)];

                        let username =
                            String::from_utf8(username.to_vec())
                                .unwrap();
                        let password =
                            String::from_utf8(password.to_vec())
                                .unwrap();

                        println!("Username: {:?}", username);
                        println!("Password: {:?}", password);

                        match proxy.get_user(username.clone()) {
                            Some(_password) => {
                                println!("User is valid");

                                if _password == password {
                                    // Write
                                    match socket
                                        .write(&[
                                            1, // Version
                                            0, // Succeeded
                                        ])
                                        .await
                                    {
                                        Ok(n) => {
                                            println!(
                                                "ACK Response sent"
                                            );
                                        }
                                        Err(e) => {
                                            println!("Error sending response");
                                        }
                                    }

                                    make_proxy(socket).await;
                                } else {
                                    match socket
                                        .write(&[
                                            1, // Version
                                            1, // Failed
                                        ])
                                        .await
                                    {
                                        Ok(n) => {
                                            println!(
                                                "ACK Response sent"
                                            );
                                        }
                                        Err(e) => {
                                            println!(
                                            "Error sending response"
                                        );
                                        }
                                    }
                                    return;
                                }
                            }
                            None => {
                                println!("User is not valid");

                                // Write
                                match socket
                                    .write(&[
                                        1, // Version
                                        1, // Failed
                                    ])
                                    .await
                                {
                                    Ok(n) => {
                                        println!("ACK Response sent");
                                    }
                                    Err(e) => {
                                        println!(
                                            "Error sending response"
                                        );
                                    }
                                }
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error reading from socket: {}", e);
                    }
                }
            } else if (methods
                .contains(&&AuthMethods::NoAuth.to_u8()))
                && proxy.check_valid_auth_method(&AuthMethods::NoAuth)
            {
                println!("NoAuth");

                // Send Accept repl

                match socket.write(&[5, 0]).await {
                    Ok(n) => {
                        println!("ACK Response sent");
                    }
                    Err(e) => {
                        println!("Error sending response");
                    }
                }

                make_proxy(socket).await;
            } else {
                println!("NotAcceptable");

                // Send NotAcceptable repl
                match socket.write(&[5, 0xff]).await {
                    Ok(n) => {
                        println!("ACK Response sent");
                    }
                    Err(e) => {
                        println!("Error sending response");
                    }
                }
            }
        }
        Err(e) => {
            println!("Error reading from socket: {}", e);
        }
    }
}

/**
 *
 * Function to proxy
 *
 *
*/
async fn make_proxy(mut socket: TcpStream) {
    let mut request: [u8; 4] = [0; 4];

    // Read First 4 bytes
    match socket.read(&mut request).await {
        Ok(n) => {
            println!("Request : {:?}", request);

            if !check_valid_version(&request[0]) {
                println!("Not socks5 version");
                return;
            }

            let command = request[1];
            let address_type = request[3];

            if address_type == 1 {
                println!("IPv4");
                // Read 4 bytes For address and 2 bytes for port
                let mut address: [u8; 6] = [0; 6];

                match socket.read(&mut address).await {
                    Ok(n) => {
                        println!("Address: {:?}", address);

                        let port = u16::from_be_bytes([
                            address[4], address[5],
                        ]);

                        println!("Port: {}", port);

                        // Connect to the server
                        let mut server_socket =
                            TcpStream::connect(format!(
                                "{}.{}.{}.{}:{}",
                                address[0],
                                address[1],
                                address[2],
                                address[3],
                                port
                            ))
                            .await
                            .unwrap();

                        // Write response
                        match socket
                            .write(&[
                                5, // Version
                                0, // Succeeded
                                0, // Reserved
                                1, // IPv4
                                address[0], address[1], address[2],
                                address[3], // Address
                                address[4], address[5], // Port
                            ])
                            .await
                        {
                            Ok(n) => {
                                println!("ACK Response sent");
                            }
                            Err(e) => {
                                println!("Error sending response");
                            }
                        }

                        // In your main function or where you set up the connections
                        let (client_reader, client_writer) =
                            io::split(socket);
                        let (server_reader, server_writer) =
                            io::split(server_socket);

                        let client_to_server =
                            tokio::spawn(bidirectional_streaming(
                                client_reader,
                                server_writer,
                            ));
                        let server_to_client =
                            tokio::spawn(bidirectional_streaming(
                                server_reader,
                                client_writer,
                            ));

                        let _ = tokio::try_join!(
                            client_to_server,
                            server_to_client
                        );
                    }
                    Err(e) => {
                        println!("Error reading from socket: {}", e);
                    }
                }
            } else if address_type == 4 {
                println!("DomainName");

                // Read 1 byte for domain name length
                let mut domain_name_length: [u8; 1] = [0; 1];

                match socket.read(&mut domain_name_length).await {
                    Ok(_n) => {
                        let domain_name_length =
                            domain_name_length[0];

                        // Read domain name
                        let mut domain_name: Vec<u8> =
                            vec![0; domain_name_length as usize];

                        match socket.read(&mut domain_name).await {
                            Ok(_n) => {
                                let domain_name =
                                    String::from_utf8(domain_name)
                                        .unwrap();
                                println!(
                                    "Domain Name: {}",
                                    domain_name
                                );

                                // Read 2 bytes for port
                                let mut port: [u8; 2] = [0; 2];

                                match socket.read(&mut port).await {
                                    Ok(_n) => {
                                        let port =
                                            u16::from_be_bytes([
                                                port[0], port[1],
                                            ]);
                                        println!("Port: {}", port);

                                        // Connect to the server
                                        let mut server_socket =
                                            TcpStream::connect(
                                                format!(
                                                    "{}:{}",
                                                    domain_name, port
                                                ),
                                            )
                                            .await
                                            .unwrap();

                                        // Write response
                                        match socket
                                            .write(&[
                                                5,
                                                0,
                                                0,
                                                3,
                                                domain_name_length,
                                                domain_name
                                                    .as_bytes()
                                                    .to_vec()
                                                    .as_slice()[0],
                                                domain_name
                                                    .as_bytes()
                                                    .to_vec()
                                                    .as_slice()[1],
                                                domain_name
                                                    .as_bytes()
                                                    .to_vec()
                                                    .as_slice()[2],
                                                domain_name
                                                    .as_bytes()
                                                    .to_vec()
                                                    .as_slice()[3],
                                                port.to_be_bytes()[0],
                                                port.to_be_bytes()[1],
                                            ])
                                            .await
                                        {
                                            Ok(n) => {
                                                println!("ACK Response sent");
                                            }
                                            Err(e) => {
                                                println!("Error sending response");
                                            }
                                        }

                                        // In your main function or where you set up the connections
                                        let (
                                            client_reader,
                                            client_writer,
                                        ) = io::split(socket);
                                        let (
                                            server_reader,
                                            server_writer,
                                        ) = io::split(server_socket);

                                        let client_to_server = tokio::spawn(bidirectional_streaming(client_reader, server_writer));
                                        let server_to_client = tokio::spawn(bidirectional_streaming(server_reader, client_writer));

                                        let _ = tokio::try_join!(
                                            client_to_server,
                                            server_to_client
                                        );
                                    }
                                    Err(e) => {
                                        println!("Error reading from socket: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "Error reading from socket: {}",
                                    e
                                );
                            }
                        }
                    }
                    Err(_e) => {
                        println!("Error reading from socket: {}", _e);
                    }
                }
            } else if address_type == 4 {
                println!("IPv6");

                // Read 16 bytes For address and 2 bytes for port
                let mut address: [u8; 18] = [0; 18];

                match socket.read(&mut address).await {
                    Ok(_n) => {
                        println!("Address: {:?}", address);

                        let port = u16::from_be_bytes([
                            address[16],
                            address[17],
                        ]);

                        println!("Port: {}", port);

                        // Connect to the server
                        let mut server_socket =
                            TcpStream::connect(format!(
                                "{}:{}:{}:{}:{}:{}:{}:{}:{}",
                                address[0],
                                address[1],
                                address[2],
                                address[3],
                                address[4],
                                address[5],
                                address[6],
                                address[7],
                                port
                            ))
                            .await
                            .unwrap();

                        // Write response Ack
                        match socket
                            .write(&[
                                5,
                                0,
                                0,
                                4,
                                address[0],
                                address[1],
                                address[2],
                                address[3],
                                address[4],
                                address[5],
                                address[6],
                                address[7],
                                port.to_be_bytes()[0],
                                port.to_be_bytes()[1],
                            ])
                            .await
                        {
                            Ok(n) => {
                                println!("ACK Response sent");
                            }
                            Err(e) => {
                                println!("Error sending response");
                            }
                        }

                        // In your main function or where you set up the connections
                        let (client_reader, client_writer) =
                            io::split(socket);
                        let (server_reader, server_writer) =
                            io::split(server_socket);

                        let client_to_server =
                            tokio::spawn(bidirectional_streaming(
                                client_reader,
                                server_writer,
                            ));

                        let server_to_client =
                            tokio::spawn(bidirectional_streaming(
                                server_reader,
                                client_writer,
                            ));

                        let _ = tokio::try_join!(
                            client_to_server,
                            server_to_client
                        );
                    }
                    Err(_e) => {
                        println!("Error reading from socket: {}", _e);
                    }
                }
            }

            return;
        }
        Err(e) => {
            println!("")
        }
    }
}
