# go-radntlm

This is a simple binary used to respond to MSCHAPv2 requests in FreeRADIUS. This can be used in other scenarios as well, but it is primarily designed to work with FreeRADIUS.

## Security Note

Pleaes do not reuse passwords from the system in other systems. Passwords are stored in a hashed format for MSCHAPv2 compatibility, but NT Hashes can be cracked with enough time and resources. It is recommended to use a strong password policy and to change passwords regularly.

## Backend Support

2 backends will be supported - flat file and a SQL server.

### Flat File Backend
Produce a flatfile with the following format:

```
username:nthash:expiration
```

The username will need to match the auth input exactly. The nthash is the NTLM hash of the user password, and the expiration is an optional field that can be used to set an expiration date for the user.

### SQL Backend

This is still under development, but the idea is a simple table with the following structure:

```sql
CREATE TABLE users (
    username VARCHAR(255) PRIMARY KEY,
    nthash VARCHAR(64) NOT NULL,
    expiration DATETIME DEFAULT NULL
);
```

## Usage

To use the binary in FreeRADIUS, go to the `mods-enabled` directory and update the `mschap` module configuration file to replace the `ntlm_auth` command with the path to the `go-radntlm` binary. For example:

```plaintext
ntlm_auth = "/path/to/go-radntlm -backend flatfile -file /path/to/users.txt --username %{User-Name} --challenge=%{%{mschap:Challenge}:-00} --nt-response=%{%{mschap:NT-Response}:-00}"
```

## But why?

MacOS and iOS devies only support PEAP-MSCHAPv2 authentication when connecting to WPA2-Enterprise networks without a network profile. This provides an alternative to connecting to SAMBA or an Active Directory server, which is not always possible in some environments.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
