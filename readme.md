# Fully Managable SOCKS5 Proxy

This project aim to create fast secure socks5 proxy server and have buildin fully managable api.

## Features

- SOCKS5
- Mutli Thread

## To-Do

- handle domain routing
- handle ipv-6 routing
- Udp based clients handing
- More clean Reply handing
- Connect and Bınd Commands
- Seting up Http server
- Handle basic ops (user Management, auth management etc.)

## Getting Started

Ensure that rust compiler istaled your computer.Start server with;

```bash
cargo run

```

You can simply test proxy working

```bash
 curl  --socks5 localhost:1080 example.com
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors

- **Abdulsamet Haymana** - _Initial work_ - [SametHaymana](https://github.com/sametHaymana)

See also the list of [contributors](https://github.com/SametHaymana/Proxier/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
