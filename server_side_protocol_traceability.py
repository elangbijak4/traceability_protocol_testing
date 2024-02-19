# Import library tinyec dan pycryptodome
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
import secrets
from tinyec import ec
import qrcode

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

# Tambahan
# Fungsi untuk mengubah string public key, string private key, dan curve name menjadi kunci publik dan kunci privat ECC
def get_ecc_public_key(public_key_string,curve_name):
  # Ubah string public key menjadi objek point
  public_key = string_to_point(public_key_string, curve_name)
  # Kembalikan kunci publik ECC
  return public_key

# Fungsi untuk mengenkripsi pesan dengan kunci publik ECC
def encrypt_ecc(message, public_key):
  # Pilih kurva eliptik yang sama dengan kunci publik
  curve = registry.get_curve(public_key.curve.name)
  # Buat kunci privat sementara (ephemeral) secara acak
  ephemeral_private_key = secrets.randbelow(curve.field.n)
  # Buat kunci publik sementara dengan mengalikan kunci privat sementara dengan generator point
  ephemeral_public_key = ephemeral_private_key * curve.g
  # Hitung kunci ECC yang dibagi dengan mengalikan kunci publik ECC dengan kunci privat sementara
  shared_ecc_key = ephemeral_private_key * public_key
  # Ubah kunci ECC yang dibagi menjadi kunci AES dengan menggunakan fungsi hash SHA256
  shared_aes_key = SHA256.new(shared_ecc_key.x.to_bytes(32, 'big')).digest()
  # Buat objek AES dengan mode GCM (Galois Counter Mode) yang mendukung autentikasi
  aes = AES.new(shared_aes_key, AES.MODE_GCM)
  # Enkripsi pesan dengan AES dan dapatkan ciphertext dan tag autentikasi
  ciphertext, tag = aes.encrypt_and_digest(message.encode('utf-8'))
  # Kembalikan ciphertext, tag, nonce, dan kunci publik sementara
  return ciphertext, tag, aes.nonce, ephemeral_public_key

# Fungsi untuk melakukan hash terhadap data
def hash_sha256_string(string):
  # Membuat string yang ingin di-hash
  string_to_hash = string
  # Membuat objek hash SHA256
  hash_object = hashlib.sha256()
  # Menambahkan data string ke objek hash
  hash_object.update(string_to_hash.encode())
  # Mendapatkan nilai hash dalam format heksadesimal
  hex_digest = hash_object.hexdigest()
  # Mengembalikasn nilai hash
  return hex_digest

def hash_string(text):
  # Membuat objek hash baru
  hash_object = SHA256.new()
  # Menambahkan data yang ingin di-hash
  hash_object.update(text.encode())
  # Mendapatkan hasil hash dalam bentuk heksadesimal
  hash_result = hash_object.hexdigest()
  # Mengembalikan hasil hash
  return hash_result

def encode_to_qrcode(string):
  # Membuat objek qrcode
  qr = qrcode.QRCode()
  # Menambahkan data ke objek qrcode
  qr.add_data(string)
  # Membuat qrcode
  img = qr.make_image()
  # Menyimpan qrcode sebagai gambar PNG
  img.save("qrcode.png")
  # Menampilkan gambar qrcode
  return img

# Berikan string public key, string private key, dan nama kurva eliptik yang Anda gunakan
public_key_string = "2a40d80e739f163bde8f2bd471a637f9ec6f17cf0e78fe497c7ea40d90e84b62955ce37843a0c7a5e10a630c4d2e1e8199c9c15d208cfa4d4692298818510e68"
curve_name = "brainpoolP256r1"
# Ubah string menjadi kunci publik dan kunci privat ECC
public_key = get_ecc_public_key(public_key_string, curve_name)
# Buat pesan yang ingin dikirim
message = '{"nzmzm":"ini percobaan bro"}'
message_hash_sha256 = hash_string(message)
# Enkripsi pesan dengan kunci publik ECC
ciphertext, tag, nonce, ephemeral_public_key = encrypt_ecc(message_hash_sha256, public_key)
# Enkode chipertext ke qrcode 
qrcode_chipertext = encode_to_qrcode(ciphertext.hex())

# Menyimpan ephemeral_public_key_string ke file
with open("tag.txt", "w") as f:
  f.write(tag.hex())

# Menyimpan ephemeral_public_key_string ke file
with open("nonce.txt", "w") as f:
  f.write(nonce.hex())

# Mengubah ephemeral_public_key menjadi string
#ephemeral_public_key_string = str(ephemeral_public_key)
#ephemeral_public_key_string = ephemeral_public_key.to_string('hex')
ephemeral_public_key_string = '%x%x' % (ephemeral_public_key.x, ephemeral_public_key.y)

# Menyimpan ephemeral_public_key_string ke file
with open("ephemeral_public_key.txt", "w") as f:
  f.write(ephemeral_public_key_string)

# Cetak ciphertext, hash, tag, nonce dan ephemeral_public_key_string
print("hash:",message_hash_sha256)
print("Ciphertext:", ciphertext.hex())
print("tag:", tag.hex())
print("nonce:", nonce.hex())
print("ephemeral_public_key_string:", ephemeral_public_key_string)
qrcode_chipertext
