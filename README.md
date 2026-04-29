NTU [Secure Systems Lab](https://liswei.sh/sslab/) fork of [Unikraft](https://github.com/unikraft/unikraft).

Changes are on other branches.

## Arm CCA
Branch `arm-cca` contains Arm CCA support for Unikraft.

Writeup: [NTU SSLab Unikraft CCA features.md](https://gist.github.com/brhiggins-gh/e3c8bd98ccf283152289ea740ebab10a)

Current features:
- `libukrsi` for basic RSI interface
- `liukarm_cca_guest` for CCA guest features
- QEMU/KVM support
- Access to QEMU static emulated devices (e.g. MMIO)

Notable features currently lacking:
- VirtIO
- Transport of attestation evidence

### Instructions for use
1. Set up Linaro's CCA QEMU RME stack, see [this guide](https://linaro.atlassian.net/wiki/spaces/QEMU/pages/29051027459/Building+an+RME+stack+for+QEMU)
2. In the menuconfig, enable `Device Drivers -> Arm CCA -> Realm
   Services Interface library & Arm CCA guest`
   - Optionally enable tests for either/both
3. Build Unikraft
4. Launch a QEMU instance as described in [Launching a Realm guest using QEMU](https://linaro.atlassian.net/wiki/spaces/QEMU/pages/29051027459/Building+an+RME+stack+for+QEMU#Launching-a-Realm-guest-using-QEMU)
5. Launch the unikernel

Note the lack of meaningful IO features limits what you can realistically run.
We recommend just building an empty Unikraft instance to see the logo output to
the terminal.
