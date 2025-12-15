const textBox = document.getElementById("textBox");
  const btn = document.getElementById("toggleBtn");

  btn.addEventListener("click", () => {
    if (textBox.dir === "ltr") {
      textBox.dir = "rtl";
      btn.textContent = "Switch to LTR";
    } else {
      textBox.dir = "ltr";
      btn.textContent = "Switch to RTL";
    }
  });

