# Rust AES Proofs
Various AES-based Proof-of-Replication and Proof-of-Time implementations and benchmarks.

### Requirements and dependencies:
Source code is written in Rust, so first of all you need to have Rust toolchain installed, the best way is to follow instructions for your platform on [rustup.rs](https://rustup.rs/).

#### System dependencies for OpenCL
Besides Rust compiler itself you'll need following components installed on your machine to run OpenCL-based implementation:
* gcc
* OpenCL drivers and development files for your GPU

On Ubuntu 18.04+ for AMD GPUs they can be installed like this:
```bash
sudo apt-get install gcc ocl-icd-opencl-dev mesa-opencl-icd
```
On Ubuntu 18.04+ for Intel GPU they can be installed like this:
```bash
sudo apt-get install gcc ocl-icd-opencl-dev beignet-opencl-icd
```

#### Software OpenCL implementation
It is also possible to use [Oclgrind](https://github.com/jrprice/Oclgrind) to run OpenCL implementation on CPU in software.

On Ubuntu 18.04+ Oclgrind can be installed like this:
```bash
sudo apt-get install oclgrind
```

### Running tests abd benchmarks
TL;DR:
```bash
cargo test
cargo bench
```

For tests built-in Rust functionality is used, so [this chapter](https://doc.rust-lang.org/book/ch11-02-running-tests.html) of Rust book will help you.

Running only subset of tests can be achieved easily like this:
```bash
cargo test -- por::aes_ni # Only run Proof-of-Replication tests and only AES-NI implementation
```

Look at `src/por` and `src/pot` subdirectories for available implementations.

For benchmarks [Criterion](https://bheisler.github.io/criterion.rs/book/index.html) is used, so you can use its documentation.

Since benchmarks may take a long time to run, you may want to only run subset of them, which can be conveniently achieved like this:
```bash
cargo bench --bench por -- OpenCL # Only run Proof-of-Replication benchmarks and only OpenCL implementation
```

Look at `benches` subdirectory for available benchmarks and implementations.
