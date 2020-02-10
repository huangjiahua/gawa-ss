function decryptMsg (data, master_key) {
    if (master_key.length < 16) {
        master_key = master_key + "j".repeat(16 - master_key.length)
    } else if (master_key.length > 16) {
        master_key = master_key.substring(0, 16);
    }
    // Decode the base64 data so we can separate iv and crypt text.
    var rawData = atob(data);
    // Split by 16 because my IV size
    var iv = rawData.substring(0, 16);
    var crypttext = rawData.substring(16);

    //Parsers
    crypttext = CryptoJS.enc.Latin1.parse(crypttext);
    iv = CryptoJS.enc.Latin1.parse(iv); 
    key = CryptoJS.enc.Utf8.parse(master_key);

    // Decrypt
    var plaintextArray = CryptoJS.AES.decrypt(
      { ciphertext:  crypttext},
      key,
      {iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7}
    );

    // Can be Utf8 too
    output_plaintext = CryptoJS.enc.Latin1.stringify(plaintextArray);
    console.log("plain text : " + output_plaintext);
    return output_plaintext;
}

function clickDoneButton() {
    let name = document.querySelector('#usr').value;
    let passwd = document.querySelector('#pwd').value;
    if (name.length === 0 || passwd.length === 0) {
        alert("请输入完整");
        return;
    }
    let content = getContent(name, passwd);
}

function getContent(name, passwd) {
    let url = window.location.href + "/" + name;
    let res = fetch(url)
        .then(response => response.json())
        .then(data => {
            let password = document.querySelector("#pwd").value;
            if (decryptMsg(data.name, password) != name) {
                document.querySelector('#result').innerHTML = "密码错误";
                alert("密码错误");
                return;
            }
            let hostAddr = decryptMsg(data.host, password);
            let port = decryptMsg(data.port, password);
            let sspass = decryptMsg(data.password, password);
            let method = decryptMsg(data.method, password);
            const content = `Host: ${hostAddr}<br>Port: ` +
                `${port}<br>Password: ${sspass}<br>Method: ${method}`;
            document.querySelector('#result').innerHTML = content;
            document.querySelector('#done').innerHTML = "确定 / 换一个";
        }).catch(() => {
            document.querySelector('#result').innerHTML = "无此用户或查询出错";
            alert("无此用户或查询出错");
        })
}