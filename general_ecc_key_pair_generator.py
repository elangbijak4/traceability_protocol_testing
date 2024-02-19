# Import library tinyec
from tinyec import registry
import secrets

# Fungsi untuk mengenerate sepasang kunci ECC dengan nama kurva eliptik sebagai argumen
def generate_ecc_keys(curve_name):
  # Dapatkan objek kurva eliptik dari registry berdasarkan nama kurva eliptik
  curve = registry.get_curve(curve_name)
  # Buat kunci privat ECC secara acak
  private_key = secrets.randbelow(curve.field.n)
  # Buat kunci publik ECC dengan mengalikan kunci privat dengan generator point
  public_key = private_key * curve.g
  # Kembalikan kunci publik dan privat ECC
  return public_key, private_key

# Contoh penggunaan fungsi di atas
# Pilih nama kurva eliptik yang diinginkan, misalnya brainpoolP256r1
curve_name = "brainpoolP256r1"
# Buat sepasang kunci ECC dengan nama kurva eliptik tersebut
public_key, private_key = generate_ecc_keys(curve_name)
# Cetak kunci ECC dalam bentuk heksadesimal
print("Public key:", public_key.x.to_bytes(32, 'big').hex() + public_key.y.to_bytes(32, 'big').hex())
print("Private key:", private_key.to_bytes(32, 'big').hex())
