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
        word.split("").forEach((letter, i) => {
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
            // Ritardo per ogni lettera in base alla posizione
            const delay = i * 100;

            if (Math.random() > 0.3 || elapsed > (duration + delay)) {
                span.textContent = word[i];
            } else {
                span.textContent = getRandomChar();
            }
        });

        if (elapsed > duration + (word.length * 100)) {
            clearInterval(interval); // Ferma il glitch dopo la durata
        }
    }, 50);
}

function startGlitchEffect() {
    glitchEffect(words[index % words.length]);
    index++;
}

setInterval(startGlitchEffect, 3000);
startGlitchEffect();
