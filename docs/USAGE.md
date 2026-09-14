# Użycie

`python app.py plik.exe --output reports`
`python app.py plik.bin --strings --output reports`
Brak zależności poza Python. Podpis Authenticode: opcjonalny PowerShell na Windows.
Hash i entropia całego pliku są liczone strumieniowo. Strings: maks. 100 ciągów
z pierwszego 1 MiB, tylko po włączeniu. MIME według rozszerzenia jest oddzielone od
rozpoznania kilku sygnatur magic. PE: podstawowy COFF, bez analizy importów i sekcji.
Nie uruchamia ani nie wysyła badanego pliku. Brak daty utworzenia na części systemów.
