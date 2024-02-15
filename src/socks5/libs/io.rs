use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub async fn bidirectional_streaming(
    mut reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
) {
    let mut buf = [0; 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                if writer.write_all(&buf[..n]).await.is_err() {
                    break; // Error or connection closed
                }
            }
            Err(_) => break, // Error reading
        }
    }
}