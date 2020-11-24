# shamirfpe

This is a project to see if I can effectively combine [Hashicorp Vault's Shamir secret sharing algorithm](https://github.com/hashicorp/vault/tree/master/shamir) with [Capital One's format preserving encryption library](https://github.com/capitalone/fpe).

```go
sf := sharmirfpe{}
sf.AddKeyPart([]byte("part1"))
sf.AddKeyPart([]byte("part2"))
sf.AddKeyPart([]byte("part3"))
// clearing key parts should be done by constructing a new shamirfpe object
sf.NewCipher(radix, maxTLen, tweak)
```
