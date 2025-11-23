const textBox = document.getElementById("textBox");
  const btn = document.getElementById("toggleBtn");

  btn.addEventListener("click", () => {
    if (textBox.dir === "ltr") {
      textBox.dir = "rtl";
      btn.textContent = "Přepnout na LTR";
    } else {
      textBox.dir = "ltr";
      btn.textContent = "Přepnout na RTL";
    }
  });

