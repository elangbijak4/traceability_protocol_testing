# Import library tinyec dan pycryptodome
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import secrets
from tinyec import ec
import cv2

# Fungsi untuk mengubah string menjadi objek point
def string_to_point(string, curve_name):
  # Pisahkan string menjadi dua bagian yang sama panjang
  half = len(string) // 2
  x_string = string[:half]
  y_string = string[half:]
  # Ubah x dan y dari heksadesimal menjadi integer
  x = int(x_string, 16)
  y = int(y_string, 16)
  # Dapatkan objek kurva eliptik dari registry
  curve = registry.get_curve(curve_name)
  # Buat objek point dengan kurva, x, dan y
  point = ec.Point(curve, x, y)
  # Kembalikan objek point
  return point

# Fungsi untuk mengubah string menjadi integer
def string_to_integer(string):
  # Ubah string dari heksadesimal menjadi integer
  integer = int(string, 16)
  # Kembalikan integer
  return integer

# Fungsi untuk mengubah string public key, string private key, dan curve name menjadi kunci publik dan kunci privat ECC
def get_ecc_private_key(private_key_string, curve_name):
  # Ubah string private key menjadi integer
  private_key = string_to_integer(private_key_string)
  # Kembalikan kunci publik dan privat ECC
  return private_key

# Fungsi untuk mendekripsi pesan dengan kunci privat ECC
def decrypt_ecc(ciphertext, tag, nonce, ephemeral_public_key, private_key):
  # Hitung kunci ECC yang dibagi dengan mengalikan kunci publik sementara dengan kunci privat ECC
  shared_ecc_key = private_key * ephemeral_public_key
  # Ubah kunci ECC yang dibagi menjadi kunci AES dengan menggunakan fungsi hash SHA256
  shared_aes_key = SHA256.new(shared_ecc_key.x.to_bytes(32, 'big')).digest()
  # Buat objek AES dengan mode GCM dan nonce yang diberikan
  aes = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
  # Dekripsi ciphertext dengan AES dan verifikasi tag autentikasi
  message = aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')
  # Kembalikan pesan yang didekripsi
  return message

# Fungsi untuk mendekode qrcode label produk
def decode_qrcode(qrcode_img_png):
  # Load the QR code image
  img = cv2.imread(qrcode_img_png)
  # Convert the image to grayscale
  gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
  # Create a QR code detector
  detector = cv2.QRCodeDetector()
  # Detect and decode the QR code
  data, bbox, _ = detector.detectAndDecode(gray)
  # Print the decoded data
  if data:
    return data
  else:
    return "No QR code found"

# dekode qrcode
qrcode_img_png = "qrcode.png"
qrcode_string = decode_qrcode(qrcode_img_png)

# Berikan string public key, nama kurva eliptik yang Anda gunakan
private_key_string = "0fa1e98f25425693110756477ae706bc19c5d7a3d27dc2618da8b5eb8e7f5e40"
curve_name = "brainpoolP256r1"

# Ubah string menjadi kunci publik dan kunci privat ECC
private_key = get_ecc_private_key(private_key_string, curve_name)

message = bytes.fromhex(qrcode_string)
# Baris ini memerlukan informasi tag, nonce dan ephemeral_public_key pada proses enkripsi sebelumnya, yang tersimpan di memori
# Dekripsi pesan dengan kunci privat ECC, dengan syarat tag, nonce dan ephemeral_public_key berasal dari server, untuk demo ini ketiganya disederhanakan tanpa harus unduh dari server, asalkan proses demo enkrip dan dekrip dalam komputer yang sama dan sesi google colab yang sama

# Membaca string hex yang berisi tag dari file
with open("tag.txt", "r") as f:
  tag_hex = f.read()

# Membaca string hex yang berisi nonce dari file
with open("nonce.txt", "r") as f:
  nonce_hex = f.read()

# Membaca string hex yang berisi ephemeral_public_key dari file
with open("ephemeral_public_key.txt", "r") as f:
  ephemeral_public_key_string = f.read()

# Mengubah string hex yang berisi tag dan nonce menjadi bertipe bytes
tag = bytes.fromhex(tag_hex)
nonce = bytes.fromhex(nonce_hex)

# Mengubah string hex yang berisi ephemeral_public_key menjadi objek poin
# Mengubah string yang berisi ephemeral_public_key menjadi objek poin
curve = registry.get_curve('brainpoolP256r1')
# Mengubah string hex yang berisi ephemeral_public_key menjadi objek poin
curve = registry.get_curve('brainpoolP256r1')
half = len(ephemeral_public_key_string) // 2
ephemeral_public_key_x = int(ephemeral_public_key_string[:half], 16)
ephemeral_public_key_y = int(ephemeral_public_key_string[half:], 16)
ephemeral_public_key = Point(curve, ephemeral_public_key_x, ephemeral_public_key_y)
#ephemeral_public_key = ec.Point(curve, ephemeral_public_key_string)

#ephemeral_public_key = ECC.import_key(bytes.fromhex(ephemeral_public_key_hex))

decrypted_message = decrypt_ecc(message, tag, nonce, ephemeral_public_key, private_key)

# Cetak pesan yang didekripsi
#print("message_for_decrypt:",message_for_decrypt)
print("Decrypted message:", decrypted_message)
