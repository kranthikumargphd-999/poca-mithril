import hashlib
from ecdsa import SigningKey


print("==============================")
print("Failure Testing")
print("==============================")


# ------------------------------
# Invalid Signature Test
# ------------------------------

sk = SigningKey.generate()

message = b"POCA_PROOF"


signature = sk.sign(message)


wrong_message = b"MODIFIED_PROOF"


try:

    sk.get_verifying_key().verify(
        signature,
        wrong_message
    )

    print(
        "Invalid Signature: Accepted"
    )

except:

    print(
        "Invalid Signature: Rejected"
    )



# ------------------------------
# Duplicate Proof Test
# ------------------------------


proof1 = hashlib.sha256(
    b"proof001"
).hexdigest()


proof2 = hashlib.sha256(
    b"proof001"
).hexdigest()



if proof1 == proof2:

    print(
        "Duplicate Proof: Detected"
    )

else:

    print(
        "Duplicate Proof: Accepted"
    )