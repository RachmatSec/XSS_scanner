import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# fungsi untuk mengambil semua forms
def get_all_forms(url):
    """Memberi sebuah 'URL' , itu akan mengembalikan semua form dari konten HTML"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """
    Fungsi ini akan mengekstrak semua informasi yang kemungkinan sangat berguna tentang form HTML
    """
    details = {}

    # Mengambil form action (target url)
    action = form.attrs.get("action", "").lower()

    # Mengambil form method (POST, GET, dan lain-lainnya)
    method = form.attrs.get("method", "get").lower()

    # Mengambil semua input details seperti type dan name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # Meletakkan semuanya menjadi sebuah kamus menghasilkan
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """
    submit sebuah form yang diberikan dalam 'form_details'
    Params:
        form_details (list): Kamus yang berisi URL informasi form (str):
        URL asli yang berisi nilai formulir (str): Ini akan diganti ke semua input teks dan pencarian
    Mengembalikan respons HTTP setelah form submission
    """
    # konstruksi penuh URL (jika URL yang disediakan dalam action itu relatif)
    target_url = urljoin(url, form_details["action"])
    # Mengambil inputan
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # menimpa semua teks dan mencari nilai dengan 'nilai'
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # Jika input nama dan hasil tidak kosong
            # kemudian tambahkan mereka ke data form submission
            data[input_name] = input_value

    print(f"[+] Memasukkan payload berbahaya ke {target_url}")
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

def scan_xss(url):
    """
    Memberikan sebuah 'url', itu mencetak semua XSS vulnerable forms dan mengembalikan nilai True jika ada yang rentan, False sebaliknya 
    """

    # ambil semua form dari URL
    forms = get_all_forms(url)
    print(f"[+] Terdeteksi {len(forms)} forms on {url}.")
    js_script = "<Script> alert('Danger XSS') </script>"

    # Mengembalikan nilai
    is_vulnerable = True

    # Iterasi pada semua forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Terdeteksi pada {url}")
            print(f"[+] Detail Form: ")
            pprint(form_details)
            is_vulnerable = False
            # Tidak akan berhenti karena kita ingin mencetak form rentan yang tersedia
    return is_vulnerable

if __name__ == "__main__":
    url = input("Masukkan URL >> ")
    print(scan_xss(url))