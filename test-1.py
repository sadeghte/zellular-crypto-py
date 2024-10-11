import cuda_crypt as cc

msg = b"4546465465465465"

pub, priv = cc.create_keypair()

sign = cc.sign(msg, pub, priv);

verified = cc.verify(msg, sign, pub);

print(f"Signature valid: {verified}")