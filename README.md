# AVBPayloadSigner

`AVBPayloadSigner` is a tool for signing payload.bin of an incremental Android A/B OTA zip.

## Usage

1. Use `openssl` to generate a private key.

    ```bash
    openssl genpkey -algorithm RSA -out ota.key
    ```

2. Ensure the [Rust toolchain](https://www.rust-lang.org/) is installed.

3. Clone this git repo and build it.

    ```bash
    cargo build --release
    ```

    The output will be in `target/release/AVBPayloadSigner.exe`.

4. Start signing by following command-lines:

    ```bash
    AVBPayloadSigner \
        --input /path/to/old/payload.bin \
        --output /path/to/new/signed/payload.bin \
        --key /path/to/ota.key
    ```
## Thanks

Based on [avbroot](https://github.com/chenxiaolong/avbroot) and references some of its code implementations.
