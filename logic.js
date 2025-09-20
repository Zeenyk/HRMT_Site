//SERVICE WORKER LOADER
            if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/service-worker.js').then(registration => {
                registration.update(); // Forza il controllo di update

                registration.onupdatefound = () => {
                    const newWorker = registration.installing;

                    newWorker.onstatechange = () => {
                    if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                        // 🔁 Auto-reload quando il nuovo SW è pronto
                        window.location.reload();
                        // Oppure mostra un messaggio personalizzato
                    }
                    };
                };
                });
            });
            }










//ANIMATION
const textElement = document.querySelector('.title');
const words = ["Ηερμετικα", "Hermetica"];
let index = 0;

function getRandomChar() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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

            if ( elapsed > (duration + delay)) {
                span.textContent = word[i];
                    
            } else {
                span.textContent = getRandomChar();
            }
        });

        if (elapsed > duration + (word.length * 100)) {
            clearInterval(interval); // Ferma il glitch dopo la durata
        }
    }, 5);
}

function startGlitchEffect() {
    glitchEffect(words[index % words.length]);
    index++;
}

setInterval(startGlitchEffect, 3000);
startGlitchEffect();