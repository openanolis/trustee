openssl genpkey -algorithm ed25519 > kbs-private.key
openssl pkey -in kbs-private.key -pubout -out kbs-public.pub