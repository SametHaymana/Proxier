use tokio::io::{
    split, AsyncReadExt, AsyncWriteExt, Error, ReadHalf,
    WriteHalf,
};
use tokio::net::TcpStream;

pub async fn connect_stream(
    socket: TcpStream,
    remote: TcpStream,
) {
    let (client_reader, client_writer) = split(socket);
    let (server_reader, server_writer) = split(remote);

    tokio::join!(
        bidirectional_streaming(
            client_reader,
            server_writer,
        ),
        bidirectional_streaming(
            server_reader,
            client_writer,
        ),
    );
}

async fn bidirectional_streaming(
    mut reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
) {
    let mut buf = [0; 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                if writer
                    .write_all(&buf[..n])
                    .await
                    .is_err()
                {
                    break; // Error or connection closed
                }
            }
            Err(_) => break, // Error reading
        }
    }
}

pub async fn connect_remote(
    address: String,
) -> Result<TcpStream, Error> {
    let stream = TcpStream::connect(address).await?;
    Ok(stream)
}
