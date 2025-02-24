const textElement = document.querySelector('.title');
const words = ["Ηερμετικα", "Hermetica"];
let index = 0;

function getRandomChar() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    return chars[Math.floor(Math.random() * chars.length)];
}

function glitchEffect(word, duration = 1000) {
    let spans = Array.from(textElement.children);
    if (spans.length !== word.length) {
        textElement.innerHTML = "";
        word.split("").forEach(letter => {
            let span = document.createElement("span");
            span.textContent = letter;
            textElement.appendChild(span);
        });
        spans = Array.from(textElement.children);
    }

    const startTime = Date.now();
    const interval = setInterval(() => {
        const elapsed = Date.now() - startTime;

        spans.forEach((span, i) => {
            if (Math.random() > 0.3 || elapsed > duration) {
                span.textContent = word[i];
            } else {
                span.textContent = getRandomChar();
            }
        });

        if (elapsed > duration) clearInterval(interval);
    }, 50);
}

function startGlitchEffect() {
    glitchEffect(words[index % words.length]);
    index++;
}

setInterval(startGlitchEffect, 2500);
startGlitchEffect();