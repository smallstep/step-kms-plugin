# step-kms-plugin

This is a tool that helps manage keys and certificates on a cloud KMSs and HSMs.
It can be used independently, or as a plugin for [`step`](https://github.com/smallstep/cli).

> ⚠️ This tool is currently in beta mode and its usage of might change without
> announcements.

## Installation

There's two installation options:

- The most generic way to install `step-kms-plugin` is to use `go install` to
compile it and install it in your `$GOBIN`, which defaults to `$(go env GOPATH)/bin`.

  ```console
  go install github.com/smallstep/step-kms-plugin@latest
  ```

- Alternatively, download the [latest release binary for your platform](https://github.com/smallstep/step-kms-plugin/releases).

To use `step-kms-plugin` as a plugin for `step` (eg. `step kms create ...`),
add it to your `$PATH` or to `$(step path --base)/plugins`.

## Supported KMSs

The following "Key Management Systems" or KMSs are supported, but not all of
them provide the full functionality:

* PKCS #11 modules
* [Amazon AWS KMS](https://aws.amazon.com/kms/)
* [Google Cloud Key Management](https://cloud.google.com/security-key-management)
* [Microsoft Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
* [YubiKey PIV](https://developers.yubico.com/PIV/)
* ssh-agent

## Usage with `step-ca`

If you're setting up a `step-ca` PKI on one of the supported KMSs, check out our [detailed tutorials in our Cryptographic Protection docs](https://smallstep.com/docs/step-ca/configuration/#cryptographic-protection).

## General Usage

`step-kms-plugin` can be used as a standalone application or in conjunction with
`step`.

The commands under `step kms` will directly call `step-kms-plugin` with the
given arguments. For example, these two commands are equivalent:

```console
step kms create --kty EC --crv P384 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1000;object=mykey?pin-value=password'
step-kms-plugin create --kty EC --crv P384 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1000;object=mykey?pin-value=password'
```

For the rest of the examples, we are going to use the plugin usage, `step kms`,
using the PKCS #11 KMS with [SoftHSM 2](https://github.com/opendnssec/SoftHSMv2).
To initialize the SoftHSM 2 we will run:

```console
$ softhsm2-util --init-token --free --token smallstep \
  --label smallstep --so-pin password --pin password
Slot 0 has a free/uninitialized token.
The token has been initialized and is reassigned to slot 715175552
```

You can later delete it running:

```console
softhsm2-util --delete-token --token smallstep
```

### Creating a new key

Our PKCS #11 implementation requires always an object id (`id=1000`) and label
(`object=my-key`) to create the key. We will add those as part of the URI that
defines the module to use.

By default, the create command creates an EC P-256 key:

```console
$ step kms create 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1000;object=my-p256?pin-value=password'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjg5Zs/fSuvfodhZQcxcu07deKsdX
sQf46/JPxQ39kPIkhD+onVVxCl462yMGVTQeLDCN3fwImoOdqZ3eKhoQOA==
-----END PUBLIC KEY-----
```

We can use `--kty`, `--crv`, and `--size` to create other types of keys. On
other KMS implementations you can also use the `--pss` and `--alg` flags to
define precisely the key to generate. Here we are creating a P-384 and a
3072-bit RSA key:

```console
$ step kms create --kty EC --crv P384 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1001;object=my-p384?pin-value=password'
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBDdy2wnC6r8n2qZTa3kefjo3CEkaWXz6
rWTbDNEYrzc9LXEoA7zI1j+liSGR9wLmu91keOBnweQOIR06QV12InEKFX2l3lRx
nDPvq7P3MeRo9UqzKlZT+D+dhYQjB54K
-----END PUBLIC KEY-----
$ step kms create --kty RSA --size 3072 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1002;object=my-rsa?pin-value=password'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzAtriAh4ABfboPff15CD
Skzxghaeb5SqcCwvZYdlZDRlZHlcbweY80bHjFvcU+ytSZOoMgBw+XooUnTmeVo3
hOy039wlZwkfv/MEL4HP1AUVNA2iS19tmybAUTK0Myl/Ui+1iGllYA3e1ChCEZwV
3B5KPfpG5KiPurhKfv5q3edIVcMKL8qj8Y9HYrzFBebQil23vkWrFylb1r/54W/O
5kT2emYEGaJ8lJqzvJaIsvQpk8EqkJ7FHuAMeZyb3BK8cGjIP/GI22mL6NO3LpFc
PK3Zjo7mZS5tQlFR9CULEbCuM+jiOs7FRJdyhUhdkygDxuWk1hfrCMYcG59P8pQX
mPaCwE78GB3Bsi50Bp4+UI9KBcp+JARdPKocd6RvASDX1KpALpFhgqrC05+JfKA+
/51QMYY1mlJn7izHmwYJr0DRn1usrh5mtJEcOtwiNKR3bo1LI00XW93DIA442IzA
KqMBZrEYmuy+oL6Jy9Ys4nOVWEzFcOjmUWyjFOMMG/89AgMBAAE=
-----END PUBLIC KEY-----
```

SoftHSM 2 does not support creating an extractable key, but on other devices, it
is recommended to use the `--extractable` flag so you can backup a wrapped
version of the new keys.

### Getting the public key

To retrieve the public key, we can use the `id`, the `object`, or both at the
same time:

```console
$ step kms key 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1000;object=my-p256?pin-value=password'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjg5Zs/fSuvfodhZQcxcu07deKsdX
sQf46/JPxQ39kPIkhD+onVVxCl462yMGVTQeLDCN3fwImoOdqZ3eKhoQOA==
-----END PUBLIC KEY-----
$ step kms key 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1001?pin-value=password'
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBDdy2wnC6r8n2qZTa3kefjo3CEkaWXz6
rWTbDNEYrzc9LXEoA7zI1j+liSGR9wLmu91keOBnweQOIR06QV12InEKFX2l3lRx
nDPvq7P3MeRo9UqzKlZT+D+dhYQjB54K
-----END PUBLIC KEY-----
$ step kms key 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;object=my-rsa?pin-value=password'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzAtriAh4ABfboPff15CD
Skzxghaeb5SqcCwvZYdlZDRlZHlcbweY80bHjFvcU+ytSZOoMgBw+XooUnTmeVo3
hOy039wlZwkfv/MEL4HP1AUVNA2iS19tmybAUTK0Myl/Ui+1iGllYA3e1ChCEZwV
3B5KPfpG5KiPurhKfv5q3edIVcMKL8qj8Y9HYrzFBebQil23vkWrFylb1r/54W/O
5kT2emYEGaJ8lJqzvJaIsvQpk8EqkJ7FHuAMeZyb3BK8cGjIP/GI22mL6NO3LpFc
PK3Zjo7mZS5tQlFR9CULEbCuM+jiOs7FRJdyhUhdkygDxuWk1hfrCMYcG59P8pQX
mPaCwE78GB3Bsi50Bp4+UI9KBcp+JARdPKocd6RvASDX1KpALpFhgqrC05+JfKA+
/51QMYY1mlJn7izHmwYJr0DRn1usrh5mtJEcOtwiNKR3bo1LI00XW93DIA442IzA
KqMBZrEYmuy+oL6Jy9Ys4nOVWEzFcOjmUWyjFOMMG/89AgMBAAE=
-----END PUBLIC KEY-----
```

### Signing

Let's first, initialize a hello world to sign:

```console
echo "Hello World" > data.txt
```

And then use the previous keys to sign, as before we can either use `id`,
`object`, or both:

```console
$ step kms sign --in data.txt 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1000;object=my-p256?pin-value=password'
MEQCIH2WfsgVRfCJs/sgIftT3i7xbpslS+9ShW/3qO9jXeA7AiBZFkcum+68zQ7pxluUE1v1yjCDyo34OEGIIyic9ItBcA==
$ step kms sign --in data.txt 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1001?pin-value=password'
MGUCMQDtK5cADG4D3AXRLeTLvOpcDoOfYHJqt8eVVhKPg+Q5z9Hk3DSBlz/h1+YGyV11crYCMEVnQIqSdYQLB096DyLrZG28+cMjKfs+mlg+UUeVShnjHgBNGt2tHCeAZAS0VV4u4A==
$ step kms sign --in data.txt 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;object=my-rsa?pin-value=password'
AYbuQf6JfQMxrnaolaOyaddW4dfHU4Rg/mXXYTzSns3WUxuxJ2yXysm2Af0DrSaoqg3J4pFAmKiadDf+AZeBi0Lwwx1GpTxxOaiGDAuCuUJyUDcA/G2mTNX9+eEQkI/vOIM6Z+5T9kqP48BN3GKV5e51feSmkP6ihnQVXhW7kgPDOWt2Qq3GjJvOrn0pIjSgiYMYviMDvgcgxPuIhktYc7ZBWW63gmZ40nR3TFzTveWn7vBCGPJMOi6eOjPKRvpzo0II5froUgbTZXXFfb0r7xhMx872i2/MlRL/xhc0iy2BEXWWcoJovrbO5SdMGM0iDDkAOYceQxqW+HPf6Ghd7KA/hP6Rr0PwpfdxW7h8fF45bHrKDCXzIY4U+tHF9E16adA5axDwHVSnO8Hm5tajhB0VM7w3DYnu3npX/ko4RJw/kXe0PzhBqr+f67mhoCOuKkrsc8p8ABensZA5LeWivo78i1KMFWkh9SMRcq728GUx5/wdkc9boYr/jFNJ4WKf
```

We can use `step` to verify one of these signatures:

```console
$ step kms key 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=1000?pin-value=password' > my-p256.key
$ step crypto key verify --key my-p256.key \
  --signature MEQCIH2WfsgVRfCJs/sgIftT3i7xbpslS+9ShW/3qO9jXeA7AiBZFkcum+68zQ7pxluUE1v1yjCDyo34OEGIIyic9ItBcA== data.txt
true
```

By default, RSA signatures use the RSA PKCS #1 scheme with SHA256, but we can
use the `--alg` to select the hash function and `--pss` to use the RSA-PSS
scheme:

```console
$ step kms sign --alg SHA512  --in data.txt 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;object=my-rsa?pin-value=password'
ljdurcImEwOgAOxntf4+U56w1+lf8V/wOWrRfMS3PvtSz3KSfRZZu10ZxtIG7ilZFNUnb0svTM9e3+ViYCOX+3zxu22F4DWp6E5S92TbS7AImQbMybl7rYtYloDBSagJ5T0d1h3wVg77Npi5Fkcn39ekWDeSmrEK359H0EJAoSFTVfYJ4vYUvFHbO5Zn/BgWQNtTVoSCDSnSX1cu3Nar9N2bAcGbbfjBcwQsjg+NDRgdxxNJESKYHL280gvZR0wLpYvX4jf57UUVLF4WdMEh1YGPsBGzO/M1rSMS8pYZVD1kNOwIq7buFGAVAgl8UirtIe0joUYQekVhFbGEgADTv33fWOa8B95ARGraR5mE0lg5vwC/8SeZL9M4iIS5cdn+lOs/Nj5GDySykpgsCPi+irqKRgMcC88omv8/ofqcUIJpm+IOhE47IvL3CjlItEJV55kQjC4qrdNb9/w4vk7fFtW/amdxb5juajU2AIfuKFduaHhwSJpyguzmi2Zc0r7e
$ step kms sign --alg SHA256 --pss  --in data.txt 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;object=my-rsa?pin-value=password'
iT/enoe6zXfz4bZolrQUoYf+B5bDhn++cfkgM4x4ozqX8xd6lljPMODGB3Z43rfvUHc3A//ULzN8DjAzA7nuExneexrlAalwhqeMHSLHAmJsztgpuQ2OHdpsEfWIbkQgd4lfZWBq0Srri32SEqTnqp+s2Itf1R1By6PFcsftVMFvH3foXn3bEwWK8gHsxLRt/bnqC7ubXU+b/xjUQiu/LMl+p7RSFVjDtm3e0j07G6cbsABsr4EA0Xlw7JRrYbiP3hz4GwfRbfSBKBXrCF+edpBhGtscJnrdwL9LD/MbaDgEWrf8lO1UFmLp2B6NsjvNiQhZJ4ruQ4isHOF669z5cFcB5Hc14i4ZI81dYAI8AjG7NZvF07bH32gM2h6vVEgesrTqqcKpLW/dge3cpcEimA0Nfzpeg6ZnhnugCtI8FBDZAbo3KP9e4O2mXydP5MmZu4vWajjWc4h3sReBFXg888j2dh8gsJXCIGNUXUzULHysfdTVivnewtW2sDDnEK+L
```

### Signing certificates with step

The `step-kms-plugin` is automatically used by `step certificate create` and
`step certificate sign` commands if we use the `--kms` flag. With these
commands, we can initialize our PKI using a key stored in a KMS.

Let's create first a root key:

```console
$ step kms create 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=2000;object=root?pin-value=password'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5fbczGkGeLrLu3nD7mbdS0PmqDUT
jT/f0r5U71dCAhP2T4rTfdrgnFPacX/a4jeQ1sMn4grtNFc1A4CE6vBt0A==
-----END PUBLIC KEY-----
```

And use it to create the root certificate:

```console
$ step certificate create --profile root-ca \
  --kms 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep?pin-value=password' \
  --key 'pkcs11:id=2000'
  "Smallstep Root CA" root_ca.crt
Your certificate has been saved in root_ca.crt.
```

Note that currently, the configuration of the KMS and the reference to the key
is passed using two different flags. This might be improved in the future.

Now let's create a key for the intermediate certificate:

```console
$ step kms create 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=2001;object=intermediate?pin-value=password'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZUm9hNkXPn9KrXrG1vzhgzTwqD4+
j0Wo9CQOP7GQApJLcVO9TGpzpLQHEUsUEU2zAnrGlxH7oFAlbZGXH4ueHQ==
-----END PUBLIC KEY-----
```

And create the intermediate ca:

```console
$ step certificate create --profile intermediate-ca \
  --kms 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep?pin-value=password' \
  --ca root_ca.crt --ca-key 'pkcs11:id=2000' \
  --key pkcs11:id=2001 \
  "Smallstep IntermediateCA" intermediate_ca.crt
Your certificate has been saved in intermediate_ca.crt.
```

We can also create a CSR backed by a key in the KMS and sign it using the intermediate key:

```console
$ step kms create 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep;id=2002;object=leaf?pin-value=password'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6fMBiDFPAOCrHSQszpoLMQX9JYuk
JVX8J8X9t/OydimJAgBujwY8xRSgnWdU1SXXdMck+wPZZNBYvcWJWpLN9Q==
-----END PUBLIC KEY-----
$ step certificate create --csr \
  --kms 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep?pin-value=password' \
  --key pkcs11:id=2002 \
  leaf.internal leaf.csr
Your certificate signing request has been saved in leaf.csr.
$ step certificate sign --kms 'pkcs11:module-path=/usr/local/lib/softhsm/libsofthsm2.so;token=smallstep?pin-value=password' \
  leaf.csr intermediate_ca.crt pkcs11:id=2001
-----BEGIN CERTIFICATE-----
MIIBxTCCAWygAwIBAgIQeauacIrgtv7uPgzk+Z4puzAKBggqhkjOPQQDAjAjMSEw
HwYDVQQDExhTbWFsbHN0ZXAgSW50ZXJtZWRpYXRlQ0EwHhcNMjIwNzEyMjE0MTI4
WhcNMjIwNzEzMjE0MTI4WjAYMRYwFAYDVQQDEw1sZWFmLmludGVybmFsMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE6fMBiDFPAOCrHSQszpoLMQX9JYukJVX8J8X9
t/OydimJAgBujwY8xRSgnWdU1SXXdMck+wPZZNBYvcWJWpLN9aOBjDCBiTAOBgNV
HQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1Ud
DgQWBBRx1wnkugvbRewcTzIyBDwkeM2qVzAfBgNVHSMEGDAWgBRWvP5Nn9rbZ5Go
24uF0oUqmHEghjAYBgNVHREEETAPgg1sZWFmLmludGVybmFsMAoGCCqGSM49BAMC
A0cAMEQCICWSdIWIStDm5OJqBlqo1fd4lpzkcM0AOQcCwer+AgO1AiAF3sK+26LI
mX6QduO/H/k8GZzcx923U54bRPCxKUaPvg==
-----END CERTIFICATE-----
```
