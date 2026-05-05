/**
 * Text-to-Speech (TTS) logic for OpsAtScale.
 * This script handles audio playback of article content.
 * It attaches to the .tts-button defined in the page actions template.
 */
document.addEventListener("DOMContentLoaded", function() {
    const mainContent = document.querySelector('.md-content__inner');
    if (!mainContent) return;

    if ('speechSynthesis' in window) {
        let availableVoices = [];
        
        const loadVoices = () => {
            availableVoices = window.speechSynthesis.getVoices();
        };
        loadVoices();
        if (speechSynthesis.onvoiceschanged !== undefined) {
            speechSynthesis.onvoiceschanged = loadVoices;
        }

        // Select the button from the template override
        const ttsButton = document.querySelector('.tts-button');
        if (!ttsButton) return;

        // Icons for swapping state
        const listenLabel = '<span class="twemoji"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77M16.5 12c0-1.77-1-3.29-2.5-4.03v8.05c1.5-.71 2.5-2.24 2.5-4.02M3 9v6h4l5 5V4L7 9H3z"/></svg></span>';
        const stopLabel = '<span class="twemoji"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2A10 10 0 0 0 2 12a10 10 0 0 0 10 10 10 10 0 0 0 10-10A10 10 0 0 0 12 2m-1 14H9V8h2v8m4 0h-2V8h2v8Z"/></svg></span>';

        let isPlaying = false;
        let utterancesQueue = [];

        function stopPlaying() {
            window.speechSynthesis.cancel();
            utterancesQueue = [];
            isPlaying = false;
            ttsButton.innerHTML = listenLabel;
            ttsButton.setAttribute("title", "Listen to article");
        }

        ttsButton.addEventListener('click', function(e) {
            e.preventDefault();
            if (isPlaying) {
                stopPlaying();
                return;
            }

            const clone = mainContent.cloneNode(true);
            
            // Cleanup the content before reading
            clone.querySelectorAll('pre, code, table, a.headerlink, .admonition, .md-content__button, hr, .md-content__tags').forEach(el => el.remove());

            // Extract blocks of text paragraph by paragraph
            const elements = Array.from(clone.querySelectorAll('p, h1, h2, h3, h4, h5, h6, li'));
            let textChunks = [];
            
            elements.forEach(el => {
                let text = el.innerText.trim();
                text = text.replace(/->/g, ' implies ');
                text = text.replace(/=>/g, ' equals ');
                if (text.length > 0) {
                    textChunks.push(text);
                }
            });

            if (textChunks.length === 0) return;
            
            if (availableVoices.length === 0) {
                availableVoices = window.speechSynthesis.getVoices();
            }
            
            // Prefer System Default voice or a local English voice
            let selectedVoice = availableVoices.find(v => v.default === true);
            if (!selectedVoice) {
                selectedVoice = availableVoices.find(v => v.lang.startsWith('en') && v.localService);
            }
            if (!selectedVoice) {
                selectedVoice = availableVoices.find(v => v.lang.startsWith('en'));
            }

            // Queue up the chunks
            utterancesQueue = textChunks.map((chunk, index) => {
                let utterance = new SpeechSynthesisUtterance(chunk);
                utterance.rate = 1.0; 
                utterance.pitch = 1.0;
                
                const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
                if (!isSafari && selectedVoice) {
                    utterance.voice = selectedVoice;
                }
                
                if (index === textChunks.length - 1) {
                    utterance.onend = stopPlaying;
                }
                return utterance;
            });

            isPlaying = true;
            ttsButton.innerHTML = stopLabel;
            ttsButton.setAttribute("title", "Stop listening");

            // Speak them sequentially
            utterancesQueue.forEach(u => window.speechSynthesis.speak(u));
        });
        
        window.addEventListener('beforeunload', () => {
            stopPlaying();
        });
    }
});
