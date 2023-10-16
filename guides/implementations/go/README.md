# OPJA Label Encryption Implementation

This is a prototype implementation of OPJA activation flow in Go. The `opjale` library is a wrapper around the [Cloudflare CIRCL](https://github.com/cloudflare/circl) library, the standard implementation of HPKE in Go. It is created to enable DSPs and matching systems to experiment with basic OPJA activation functionality such as generating OPJA key pairs and encrypting/decrypting OPJA labels. The package `main` inside `opjale` provides a simplified end-to-end flow of the OPJA activation functionality. Note that this is a reference implementation and is not vetted for a *production* environment.

## Quick Strart Guide

### Install Go

Install [Go](https://go.dev/). The minimum version required is 1.18.

### Clone

Clone the repository and make `opja/guides/implementations/go/opjale` as the current working directory.

<div>
<pre>
git clone https://github.com/IABTechLab/opja.git
cd opja/guides/implementations/go/opjale
</pre>
</div>

### Test

Use the test command to run tests.

<div>
<pre>
make test
</pre>
</div>

### Run

Build and run the project using the run command.

<div>
<pre>
make run
</pre>
</div>

The resulting binary `main` can be found in `./main`. To just build the project, run `make build` instead.

### Clean

Finally, run the clean command to remove the binary.

<div>
<pre>
make clean
</pre>
</div>
