#!/usr/bin/env bash
# Synthetic voices for bench/probe-translate.js and bench/interpreter-bench.js.
# macOS only (say, afconvert). The WAVs are committed; rerun only to change a
# text. Every voice gets the same set: three phrases, a one-word reply, and
# ~25 s of speech for its voice print.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p fixtures
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

render() { # <voice> <file-stem> <text>
  say -v "$1" -o "$tmp/$2.aiff" "$3"
  afconvert -f WAVE -d LEI16@24000 -c 1 "$tmp/$2.aiff" "fixtures/$2.wav"
}

render Milena ru-1 "Добрый день. Я хотел бы обсудить условия поставки на следующий месяц."
render Milena ru-2 "Цена нас устраивает, но сроки нужно сократить до двух недель."
render Milena ru-3 "Пожалуйста, пришлите нам заказ по электронной почте."
render Milena ru-short "Да."
render Milena ru-enroll "Меня зовут Милена. Я работаю в отделе закупок и каждый день разговариваю с поставщиками из разных стран. Обычно мы обсуждаем цены, сроки доставки, качество товара и условия оплаты. Иногда разговор затягивается, потому что нужно уточнить много деталей, но в итоге мы всегда находим решение, которое устраивает обе стороны. Вечером я люблю гулять в парке и читать книги о путешествиях."

render Anna de-1 "Guten Tag. Wir können die Ware bis Ende des Monats liefern."
render Anna de-2 "Der Preis ist fest, aber über die Lieferzeit können wir sprechen."
render Anna de-3 "Bitte schicken Sie uns die Bestellung per E-Mail."
render Anna de-short "Ja."
render Anna de-enroll "Mein Name ist Anna. Ich arbeite im Vertrieb und spreche jeden Tag mit Kunden aus verschiedenen Ländern. Meistens geht es um Preise, Lieferzeiten, die Qualität der Ware und die Zahlungsbedingungen. Manchmal dauert ein Gespräch länger, weil viele Details zu klären sind, aber am Ende finden wir immer eine Lösung, die für beide Seiten passt. Am Abend gehe ich gern im Park spazieren und lese Bücher über Reisen."

render Laura sk-1 "Dobrý deň. Tovar môžeme dodať do konca mesiaca."
render Laura sk-2 "Cena je pevná, ale o termíne dodania sa môžeme porozprávať."
render Laura sk-3 "Prosím, pošlite nám objednávku e-mailom."
render Laura sk-short "Áno."
render Laura sk-enroll "Volám sa Laura. Pracujem v obchodnom oddelení a každý deň hovorím so zákazníkmi z rôznych krajín. Väčšinou sa rozprávame o cenách, termínoch dodania, kvalite tovaru a platobných podmienkach. Niekedy rozhovor trvá dlhšie, pretože treba vyjasniť veľa detailov, ale nakoniec vždy nájdeme riešenie, ktoré vyhovuje obom stranám. Večer sa rada prechádzam v parku a čítam knihy o cestovaní."
