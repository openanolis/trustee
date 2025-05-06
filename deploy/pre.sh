openssl genpkey -algorithm ed25519 > kbs-private.key
openssl pkey -in kbs/config/private.key -pubout -out kbs-public.pub