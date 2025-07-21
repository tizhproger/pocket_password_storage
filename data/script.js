let salt = "";
let masterKeyHex = "";

// Загрузка соли с сервера
async function loadSalt() {
    try {
        const resp = await fetch('/getSalt');
        if (!resp.ok) throw new Error("Ошибка получения соли");
        const data = await resp.json();
        salt = data.salt;
        console.log("✅ Загружена соль:", salt);
    } catch (err) {
        console.error("Ошибка загрузки соли:", err);
        alert("Ошибка соединения с устройством или авторизации");
    }
}

// Вычисление PBKDF2 ключа на клиенте
async function calculateKey(password) {
  if (!salt) await loadSalt();
  return CryptoJS.PBKDF2(
     password,
     CryptoJS.enc.Hex.parse(salt),
     { keySize:128/32, iterations:10000, hasher:CryptoJS.algo.SHA256 }
   ).toString(CryptoJS.enc.Hex);
}

// Автоматическая авторизация перед каждым API-запросом
async function authorizedFetch(url, options = {}) {
  const token = sessionStorage.getItem('pps_token');
  if (!token) { location.href='/login.html'; return; }

  if (!options.headers) options.headers = {};
  options.headers['Authorization'] = 'Bearer '+token;
  options.headers['X-Requested-With'] = 'XMLHttpRequest';

  return fetch(url, options);
}

async function loadPasswords() {
  const response = await authorizedFetch('/getPasswords');
  if (!response.ok) { alert("Unauthorized"); location.href = "/login.html"; return; }

  const text = await response.text();
  if (!text || text.trim() === "[]") {
    document.getElementById("passwordList").innerHTML =
      '<tr><td>No saved passwords.</td></tr>';
    return;
  }

  /** ---------- ❶ Собираем все ключи ---------- */
  const entries = JSON.parse(text);
  const base = ["site", "login", "password"];
  const extras = new Set();

  entries.forEach(e =>
    Object.keys(e).forEach(k => {
      if (!base.includes(k)) extras.add(k);
    })
  );

  const columns = [...base, ...extras];     // без Actions
  const thead   = document.getElementById("passwordHeader");
  const tbody   = document.getElementById("passwordList");

  /** ---------- ❷ Рисуем шапку ---------- */
  thead.innerHTML = "";
  const headRow = thead.insertRow();
  columns.concat("actions").forEach(col => {
    const th = document.createElement("th");
    th.textContent =
      col === "actions" ? "Actions" : col.charAt(0).toUpperCase() + col.slice(1);
    headRow.appendChild(th);
  });

  /** ---------- ❸ Рисуем строки ---------- */
  tbody.innerHTML = "";
  entries.forEach((entry, idx) => {
    const row = tbody.insertRow();

    // обычные ячейки
    columns.forEach(key => {
	  const cell          = row.insertCell();
	  const value         = entry[key] ?? "";

	  cell.textContent    = value;
	  cell.title          = value;           // ← подсказка с полным текстом
	  cell.classList.add("truncate");
	  
	  cell.onclick = () => {
		  const dlg = document.createElement("dialog");
		  dlg.innerText = value;
		  dlg.style.padding = "20px";
		  document.body.appendChild(dlg);
		  dlg.showModal();
		  dlg.onclick = () => { dlg.close(); dlg.remove(); };
		};
	});

    // actions
    const act = row.insertCell();
    ["Delete", "Edit"].forEach(label => {
      const btn = document.createElement("button");
      btn.textContent = label;
      if (label === "Delete") {
        btn.onclick = async () => {
          await authorizedFetch('/deletePassword', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ index: idx })
			  });
			  loadPasswords();
			};
      } else {
        btn.onclick = async () => {
          const updated = { index: idx };
		  columns.forEach(k => {
		  const val = prompt(`New ${k}`, entry[k] ?? "");
		  if (val !== null && val !== entry[k])
			  updated[k] = val;
		    });

			  const resp = await authorizedFetch('/editPassword', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(updated)
			  });
			  if (resp.ok) loadPasswords(); else alert("Failed to edit entry");
			};
      }
      act.appendChild(btn);
    });
  });
}

async function exportPasswords() {
    const response = await authorizedFetch('/exportPasswords');
    if (response.ok) {
        const data = await response.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "passwords_backup.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    } else {
        alert("Failed to export passwords!");
    }
}

async function importPasswords(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
        const response = await authorizedFetch('/importPasswords', {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: e.target.result
        });

        if (response.ok) {
            loadPasswords();
        } else {
            alert("Failed to import passwords!");
        }
    };
    reader.readAsText(file);
}

function generatePassword() {
    const length = 12;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let retVal = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    document.getElementById("password").value = retVal;
}

function addField() {
    const fieldsContainer = document.getElementById("fieldsContainer");

    const keyInput = document.createElement("input");
    keyInput.className = "custom-key";
    keyInput.placeholder = "Custom Field Name";

    const valueInput = document.createElement("input");
    valueInput.className = "custom-value";
    valueInput.placeholder = "Custom Field Value";

    fieldsContainer.appendChild(keyInput);
    fieldsContainer.appendChild(valueInput);
}

async function addPassword() {
    const entry = {
        site: document.getElementById("site").value,
        login: document.getElementById("login").value,
        password: document.getElementById("password").value
    };

    const keys = document.querySelectorAll(".custom-key");
    const values = document.querySelectorAll(".custom-value");

    for (let i = 0; i < keys.length; i++) {
        const key = keys[i].value.trim();
        const value = values[i].value.trim();
        if (key && value) {
            entry[key] = value;
        }
    }

    const response = await authorizedFetch('/addPassword', {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(entry)
    });

    if (response.ok) {
        alert("✅ Password added!");
        loadPasswords();
    } else {
        alert("❌ Failed to add password.");
    }
}

async function saveWiFi() {
	  const ssid = document.getElementById('ssid').value.trim();
	  const password = document.getElementById('wifiPassword').value.trim();
	  const apSsid = document.getElementById('apSsid').value.trim();
	  const apPassword = document.getElementById('apPassword').value.trim();

	  if (!ssid) {
		alert('Введите SSID Wi-Fi');
		return;
	  }

	  const passwordStorage = sessionStorage.getItem('pps_password');
	  if (!passwordStorage) {
		alert('Нет сохранённого пароля. Войдите снова.');
		window.location.href = '/login.html';
		return;
	  }

	  const saltResponse = await authorizedFetch('/getSalt');
	  const saltData = await saltResponse.json();
	  const salt = saltData.salt;

	  const resp = await authorizedFetch('/saveSettings', {
		  method: 'POST',
		  headers: {
			'Content-Type': 'application/json'
		  },
		  body: JSON.stringify({
			ssid,
			password,
			ap_ssid: apSsid,
			ap_password: apPassword
		  })
		});

	  if (resp.ok) {
		alert('✅ Настройки Wi-Fi успешно сохранены! Устройство перезагрузится.');
		setTimeout(() => window.location.href = '/login.html', 3000);
	  } else {
		alert('❌ Ошибка сохранения настроек');
	  }
	};
	
async function loadCurrentSettings() {
  try {
	const resp = await authorizedFetch('/settings');
	if (!resp.ok) throw new Error('Не удалось загрузить настройки');
	const data = await resp.json();

	if (data.ssid) document.getElementById('ssid').value = data.ssid;
	if (data.password) document.getElementById('wifiPassword').value = data.password;
	if (data.ap_ssid) document.getElementById('apSsid').value = data.ap_ssid;
	if (data.ap_password) document.getElementById('apPassword').value = data.ap_password;
  } catch (err) {
	console.error(err);
  }
};

async function initPassword() {
  await loadSalt();
  const p1 = document.getElementById('password1').value.trim();
  const p2 = document.getElementById('password2').value.trim();

  if (p1.length < 4) {
    alert('Пароль слишком короткий');
    return;
  }
  if (p1 !== p2) {
    alert('Пароли не совпадают');
    return;
  }

  const resp = await fetch('/initKey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: p1 })
  });

  if (!resp.ok) {
    alert('Ошибка инициализации');
  } else {
    alert('Пароль установлен. Перезапуск...');
    window.location.href = '/login.html';
  }
};

async function login() {
    try {
        await loadSalt();
        const password = document.getElementById('password').value.trim();
        if (!password) {
            alert("Введите пароль!");
            return;
        }
        const resp = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password })
        });
        if (resp.ok) {
            const data = await resp.json();
            sessionStorage.setItem("pps_token", data.token);
            window.location.href = "/index.html";
        } else {
            const text = await resp.text();
            alert("Ошибка входа: " + text);
        }
    } catch (err) {
        console.error("Ошибка в login():", err);
        alert("Ошибка во время входа: " + err);
    }
}

function logout() {
    sessionStorage.removeItem("pps_token");
    window.location.href = "/login.html";
}

if (document.getElementById("passwordList")) {
    loadPasswords();
}

if (document.getElementById("ssid")) {
    loadCurrentSettings();
}

if (document.getElementById("exportPasswords")) {
    document.getElementById("exportPasswords").addEventListener("click", exportPasswords);
}

if (document.getElementById("importPasswords")) {
    document.getElementById("importPasswords").addEventListener("change", importPasswords);
}
