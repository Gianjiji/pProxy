"use strict";
/*
 * pProxy UI localization (IT, EN, ES, FR, PT, DE).
 *
 * Strategy: the Italian source text is the canonical key. At load (and on every
 * language switch) the DOM is walked; each element whose innerHTML matches a key
 * is translated as a block, otherwise its bare text nodes are translated one by
 * one (so labels that wrap an <input>, and <p> with dynamic <span>/<code>
 * children, keep their live content intact). Placeholders, the <title> and
 * <html lang> are handled too. app.js routes its dynamic strings through
 * window.i18nT(). Matching is whitespace-insensitive (runs collapsed + trimmed).
 */
(function () {
  const LANGS = ["en", "es", "fr", "pt", "de"]; // index order of the arrays below
  const LANGS_UI = [
    ["it", "Italiano"], ["en", "English"], ["es", "Español"],
    ["fr", "Français"], ["pt", "Português"], ["de", "Deutsch"],
  ];
  const SUPPORTED = new Set(["it", ...LANGS]);
  const STORE_KEY = "pproxy_lang";

  // key (Italian source) -> [en, es, fr, pt, de]
  const STRINGS = {
    // ---- shared / index ----
    [`pProxy — Privacy Proxy per LLM`]: [`pProxy — Privacy Proxy for LLMs`, `pProxy — Proxy de privacidad para LLM`, `pProxy — Proxy de confidentialité pour LLM`, `pProxy — Proxy de privacidade para LLM`, `pProxy — Datenschutz-Proxy für LLMs`],
    [`📖 Guida`]: [`📖 Guide`, `📖 Guía`, `📖 Guide`, `📖 Guia`, `📖 Anleitung`],
    [`Anonimizza i dati sensibili prima di darli a un'AI, poi ripristina gli originali nella risposta. La mappa dei dati reali resta sul server (sessione temporanea) o, in modalità zero-knowledge, solo nel tuo browser.`]: [
      `Anonymize sensitive data before sending it to an AI, then restore the originals in the response. The map of the real data stays on the server (temporary session) or, in zero-knowledge mode, only in your browser.`,
      `Anonimiza los datos sensibles antes de dárselos a una IA y luego restaura los originales en la respuesta. El mapa de los datos reales permanece en el servidor (sesión temporal) o, en modo zero-knowledge, solo en tu navegador.`,
      `Anonymisez les données sensibles avant de les transmettre à une IA, puis restaurez les originaux dans la réponse. La table des données réelles reste sur le serveur (session temporaire) ou, en mode zero-knowledge, uniquement dans votre navigateur.`,
      `Anonimize os dados sensíveis antes de os dar a uma IA e depois restaure os originais na resposta. O mapa dos dados reais permanece no servidor (sessão temporária) ou, no modo zero-knowledge, apenas no seu navegador.`,
      `Anonymisieren Sie sensible Daten, bevor Sie sie einer KI geben, und stellen Sie die Originale dann in der Antwort wieder her. Die Zuordnung der echten Daten bleibt auf dem Server (temporäre Sitzung) oder, im Zero-Knowledge-Modus, nur in Ihrem Browser.`],
    [`API key`]: [`API key`, `Clave API`, `Clé API`, `Chave API`, `API-Schlüssel`],
    [`(solo se il server la richiede)`]: [`(only if the server requires it)`, `(solo si el servidor la requiere)`, `(seulement si le serveur l'exige)`, `(apenas se o servidor a exigir)`, `(nur wenn der Server ihn verlangt)`],
    [`1 · Anonimizza`]: [`1 · Anonymize`, `1 · Anonimizar`, `1 · Anonymiser`, `1 · Anonimizar`, `1 · Anonymisieren`],
    [`2 · Ripristina`]: [`2 · Restore`, `2 · Restaurar`, `2 · Restaurer`, `2 · Restaurar`, `2 · Wiederherstellen`],
    [`Pipeline LLM`]: [`LLM pipeline`, `Pipeline LLM`, `Pipeline LLM`, `Pipeline LLM`, `LLM-Pipeline`],
    [`Sessioni`]: [`Sessions`, `Sesiones`, `Sessions`, `Sessões`, `Sitzungen`],
    [`Incolla il testo (o carica un file), ottieni la versione con i placeholder <code>[EMAIL_001]</code>… da dare alla tua AS. Poi vai su <b>Ripristina</b>.`]: [
      `Paste the text (or upload a file) and get the version with placeholders like <code>[EMAIL_001]</code>… to give to your AI. Then go to <b>Restore</b>.`,
      `Pega el texto (o sube un archivo) y obtén la versión con marcadores <code>[EMAIL_001]</code>… para dársela a tu IA. Luego ve a <b>Restaurar</b>.`,
      `Collez le texte (ou importez un fichier) et obtenez la version avec des espaces réservés <code>[EMAIL_001]</code>… à donner à votre IA. Allez ensuite dans <b>Restaurer</b>.`,
      `Cole o texto (ou carregue um ficheiro) e obtenha a versão com marcadores <code>[EMAIL_001]</code>… para dar à sua IA. Depois vá a <b>Restaurar</b>.`,
      `Fügen Sie den Text ein (oder laden Sie eine Datei hoch) und erhalten Sie die Version mit Platzhaltern wie <code>[EMAIL_001]</code>…, die Sie Ihrer KI geben. Gehen Sie dann zu <b>Wiederherstellen</b>.`],
    [`Testo`]: [`Text`, `Texto`, `Texte`, `Texto`, `Text`],
    [`…oppure carica un file (TXT, JSON, CSV, PDF, DOCX)`]: [`…or upload a file (TXT, JSON, CSV, PDF, DOCX)`, `…o sube un archivo (TXT, JSON, CSV, PDF, DOCX)`, `…ou importez un fichier (TXT, JSON, CSV, PDF, DOCX)`, `…ou carregue um ficheiro (TXT, JSON, CSV, PDF, DOCX)`, `…oder laden Sie eine Datei hoch (TXT, JSON, CSV, PDF, DOCX)`],
    [`Opzioni`]: [`Options`, `Opciones`, `Options`, `Opções`, `Optionen`],
    [`Confidenza`]: [`Confidence`, `Confianza`, `Confiance`, `Confiança`, `Konfidenz`],
    [`Tipi entità`]: [`Entity types`, `Tipos de entidad`, `Types d'entité`, `Tipos de entidade`, `Entitätstypen`],
    [`NER avanzato`]: [`Advanced NER`, `NER avanzado`, `NER avancé`, `NER avançado`, `Erweitertes NER`],
    [`Mostra valori rilevati`]: [`Show detected values`, `Mostrar valores detectados`, `Afficher les valeurs détectées`, `Mostrar valores detetados`, `Erkannte Werte anzeigen`],
    [`Zero-knowledge (mappa nel browser)`]: [`Zero-knowledge (map in browser)`, `Zero-knowledge (mapa en el navegador)`, `Zero-knowledge (table dans le navigateur)`, `Zero-knowledge (mapa no navegador)`, `Zero-Knowledge (Zuordnung im Browser)`],
    [`Anonimizza`]: [`Anonymize`, `Anonimizar`, `Anonymiser`, `Anonimizar`, `Anonymisieren`],
    [`← premi qui per avviare (o Ctrl/Cmd+Invio nel testo)`]: [`← click here to start (or Ctrl/Cmd+Enter in the text)`, `← pulsa aquí para iniciar (o Ctrl/Cmd+Intro en el texto)`, `← cliquez ici pour lancer (ou Ctrl/Cmd+Entrée dans le texte)`, `← clique aqui para iniciar (ou Ctrl/Cmd+Enter no texto)`, `← hier klicken zum Starten (oder Strg/Cmd+Enter im Text)`],
    [`Testo anonimizzato`]: [`Anonymized text`, `Texto anonimizado`, `Texte anonymisé`, `Texto anonimizado`, `Anonymisierter Text`],
    [`Copia`]: [`Copy`, `Copiar`, `Copier`, `Copiar`, `Kopieren`],
    [`Sessione:`]: [`Session:`, `Sesión:`, `Session :`, `Sessão:`, `Sitzung:`],
    [`Entità rilevate`]: [`Detected entities`, `Entidades detectadas`, `Entités détectées`, `Entidades detetadas`, `Erkannte Entitäten`],
    [`Mappa (zero-knowledge)`]: [`Map (zero-knowledge)`, `Mapa (zero-knowledge)`, `Table (zero-knowledge)`, `Mapa (zero-knowledge)`, `Zuordnung (Zero-Knowledge)`],
    [`Copia mappa`]: [`Copy map`, `Copiar mapa`, `Copier la table`, `Copiar mapa`, `Zuordnung kopieren`],
    [`Incolla qui la <b>risposta della tua AI</b> (quella che contiene i placeholder <code>[EMAIL_001]</code>…). pProxy ricostruisce i dati originali.`]: [
      `Paste here the <b>response from your AI</b> (the one containing placeholders like <code>[EMAIL_001]</code>…). pProxy rebuilds the original data.`,
      `Pega aquí la <b>respuesta de tu IA</b> (la que contiene los marcadores <code>[EMAIL_001]</code>…). pProxy reconstruye los datos originales.`,
      `Collez ici la <b>réponse de votre IA</b> (celle qui contient les espaces réservés <code>[EMAIL_001]</code>…). pProxy reconstruit les données originales.`,
      `Cole aqui a <b>resposta da sua IA</b> (a que contém os marcadores <code>[EMAIL_001]</code>…). pProxy reconstrói os dados originais.`,
      `Fügen Sie hier die <b>Antwort Ihrer KI</b> ein (die mit den Platzhaltern <code>[EMAIL_001]</code>…). pProxy stellt die Originaldaten wieder her.`],
    [`Risposta dell'AI (con i placeholder)`]: [`AI response (with placeholders)`, `Respuesta de la IA (con marcadores)`, `Réponse de l'IA (avec espaces réservés)`, `Resposta da IA (com marcadores)`, `KI-Antwort (mit Platzhaltern)`],
    [`ID sessione`]: [`Session ID`, `ID de sesión`, `ID de session`, `ID de sessão`, `Sitzungs-ID`],
    [`(compilato in automatico dopo l'anonimizzazione)`]: [`(filled in automatically after anonymization)`, `(se rellena automáticamente tras la anonimización)`, `(rempli automatiquement après l'anonymisation)`, `(preenchido automaticamente após a anonimização)`, `(wird nach der Anonymisierung automatisch ausgefüllt)`],
    [`Modalità zero-knowledge attiva: verrà usata la mappa salvata nel browser (l'ID sessione è ignorato).`]: [
      `Zero-knowledge mode active: the map saved in the browser will be used (the session ID is ignored).`,
      `Modo zero-knowledge activo: se usará el mapa guardado en el navegador (el ID de sesión se ignora).`,
      `Mode zero-knowledge actif : la table enregistrée dans le navigateur sera utilisée (l'ID de session est ignoré).`,
      `Modo zero-knowledge ativo: será usado o mapa guardado no navegador (o ID de sessão é ignorado).`,
      `Zero-Knowledge-Modus aktiv: Es wird die im Browser gespeicherte Zuordnung verwendet (die Sitzungs-ID wird ignoriert).`],
    [`Ripristina dati originali`]: [`Restore original data`, `Restaurar datos originales`, `Restaurer les données originales`, `Restaurar dados originais`, `Originaldaten wiederherstellen`],
    [`← premi qui per avviare`]: [`← click here to start`, `← pulsa aquí para iniciar`, `← cliquez ici pour lancer`, `← clique aqui para iniciar`, `← hier klicken zum Starten`],
    [`Testo ripristinato`]: [`Restored text`, `Texto restaurado`, `Texte restauré`, `Texto restaurado`, `Wiederhergestellter Text`],
    [`Tutto in un colpo: pProxy anonimizza, chiama l'AI <b>al posto tuo</b> (chiave API lato server) e ti restituisce la risposta già ripristinata. Usa <code>demo</code> per provare senza chiave.`]: [
      `All in one go: pProxy anonymizes, calls the AI <b>for you</b> (server-side API key) and returns the already-restored response. Use <code>demo</code> to try without a key.`,
      `Todo de una vez: pProxy anonimiza, llama a la IA <b>en tu lugar</b> (clave API en el servidor) y te devuelve la respuesta ya restaurada. Usa <code>demo</code> para probar sin clave.`,
      `Tout en une fois : pProxy anonymise, appelle l'IA <b>à votre place</b> (clé API côté serveur) et vous renvoie la réponse déjà restaurée. Utilisez <code>demo</code> pour essayer sans clé.`,
      `Tudo de uma vez: pProxy anonimiza, chama a IA <b>por si</b> (chave API no servidor) e devolve-lhe a resposta já restaurada. Use <code>demo</code> para experimentar sem chave.`,
      `Alles auf einmal: pProxy anonymisiert, ruft die KI <b>für Sie</b> auf (API-Schlüssel serverseitig) und gibt Ihnen die bereits wiederhergestellte Antwort zurück. Nutzen Sie <code>demo</code>, um es ohne Schlüssel auszuprobieren.`],
    [`…oppure carica un file`]: [`…or upload a file`, `…o sube un archivo`, `…ou importez un fichier`, `…ou carregue um ficheiro`, `…oder laden Sie eine Datei hoch`],
    [`Provider`]: [`Provider`, `Proveedor`, `Fournisseur`, `Fornecedor`, `Anbieter`],
    [`demo (senza API key)`]: [`demo (no API key)`, `demo (sin clave API)`, `demo (sans clé API)`, `demo (sem chave API)`, `demo (ohne API-Schlüssel)`],
    [`Modello`]: [`Model`, `Modelo`, `Modèle`, `Modelo`, `Modell`],
    [`Istruzione (usa <code>{document}</code> come segnaposto del testo)`]: [
      `Instruction (use <code>{document}</code> as the text placeholder)`,
      `Instrucción (usa <code>{document}</code> como marcador del texto)`,
      `Instruction (utilisez <code>{document}</code> comme espace réservé du texte)`,
      `Instrução (use <code>{document}</code> como marcador do texto)`,
      `Anweisung (verwenden Sie <code>{document}</code> als Platzhalter für den Text)`],
    [`Analizza il seguente testo:\n\n{document}`]: [`Analyze the following text:\n\n{document}`, `Analiza el siguiente texto:\n\n{document}`, `Analysez le texte suivant :\n\n{document}`, `Analise o seguinte texto:\n\n{document}`, `Analysieren Sie den folgenden Text:\n\n{document}`],
    [`System prompt (opzionale)`]: [`System prompt (optional)`, `System prompt (opcional)`, `System prompt (optionnel)`, `System prompt (opcional)`, `System-Prompt (optional)`],
    [`Max chunk`]: [`Max chunk`, `Fragmento máx.`, `Bloc max.`, `Bloco máx.`, `Max. Block`],
    [`Esegui pipeline`]: [`Run pipeline`, `Ejecutar pipeline`, `Exécuter la pipeline`, `Executar pipeline`, `Pipeline ausführen`],
    [`Risposta finale (dati ripristinati)`]: [`Final response (restored data)`, `Respuesta final (datos restaurados)`, `Réponse finale (données restaurées)`, `Resposta final (dados restaurados)`, `Endgültige Antwort (wiederhergestellte Daten)`],
    [`Dettagli (testo anonimizzato e risposta grezza dell'AI)`]: [`Details (anonymized text and raw AI response)`, `Detalles (texto anonimizado y respuesta cruda de la IA)`, `Détails (texte anonymisé et réponse brute de l'IA)`, `Detalhes (texto anonimizado e resposta bruta da IA)`, `Details (anonymisierter Text und Roh-Antwort der KI)`],
    [`Risposta AI (con placeholder)`]: [`AI response (with placeholders)`, `Respuesta de la IA (con marcadores)`, `Réponse de l'IA (avec espaces réservés)`, `Resposta da IA (com marcadores)`, `KI-Antwort (mit Platzhaltern)`],
    [`· Sessione:`]: [`· Session:`, `· Sesión:`, `· Session :`, `· Sessão:`, `· Sitzung:`],
    [`Controlla o elimina una sessione lato server. L'ID sessione è una credenziale: chi lo possiede può ripristinare i dati, quindi non condividerlo.`]: [
      `Check or delete a session on the server. The session ID is a credential: anyone who has it can restore the data, so don't share it.`,
      `Comprueba o elimina una sesión en el servidor. El ID de sesión es una credencial: quien lo tenga puede restaurar los datos, así que no lo compartas.`,
      `Vérifiez ou supprimez une session côté serveur. L'ID de session est un identifiant : quiconque le possède peut restaurer les données, ne le partagez donc pas.`,
      `Verifique ou elimine uma sessão no servidor. O ID de sessão é uma credencial: quem o tiver pode restaurar os dados, por isso não o partilhe.`,
      `Überprüfen oder löschen Sie eine Sitzung auf dem Server. Die Sitzungs-ID ist ein Zugangsschlüssel: Wer sie besitzt, kann die Daten wiederherstellen – teilen Sie sie daher nicht.`],
    [`Stato`]: [`Status`, `Estado`, `État`, `Estado`, `Status`],
    [`Elimina`]: [`Delete`, `Eliminar`, `Supprimer`, `Eliminar`, `Löschen`],

    // ---- placeholders ----
    [`Incolla qui il testo con dati sensibili…`]: [`Paste here the text with sensitive data…`, `Pega aquí el texto con datos sensibles…`, `Collez ici le texte contenant des données sensibles…`, `Cole aqui o texto com dados sensíveis…`, `Fügen Sie hier den Text mit sensiblen Daten ein…`],
    [`es. EMAIL,PHONE,CF (vuoto = tutti)`]: [`e.g. EMAIL,PHONE,CF (empty = all)`, `p. ej. EMAIL,PHONE,CF (vacío = todos)`, `ex. EMAIL,PHONE,CF (vide = tous)`, `ex. EMAIL,PHONE,CF (vazio = todos)`, `z. B. EMAIL,PHONE,CF (leer = alle)`],
    [`Incolla qui l'output dell'AI…`]: [`Paste here the AI output…`, `Pega aquí la salida de la IA…`, `Collez ici la sortie de l'IA…`, `Cole aqui a saída da IA…`, `Fügen Sie hier die KI-Ausgabe ein…`],
    [`Incolla qui il testo…`]: [`Paste here the text…`, `Pega aquí el texto…`, `Collez ici le texte…`, `Cole aqui o texto…`, `Fügen Sie hier den Text ein…`],
    [`(default del provider)`]: [`(provider default)`, `(predeterminado del proveedor)`, `(par défaut du fournisseur)`, `(predefinição do fornecedor)`, `(Standard des Anbieters)`],
    [`(opzionale)`]: [`(optional)`, `(opcional)`, `(optionnel)`, `(opcional)`, `(optional)`],
    [`vuoto = tutti`]: [`empty = all`, `vacío = todos`, `vide = tous`, `vazio = todos`, `leer = alle`],

    // ---- guide ----
    [`pProxy — Guida all'uso`]: [`pProxy — User guide`, `pProxy — Guía de uso`, `pProxy — Guide d'utilisation`, `pProxy — Guia de utilização`, `pProxy — Bedienungsanleitung`],
    [`Guida a pProxy`]: [`pProxy guide`, `Guía de pProxy`, `Guide de pProxy`, `Guia do pProxy`, `pProxy-Anleitung`],
    [`← Torna all'app`]: [`← Back to the app`, `← Volver a la app`, `← Retour à l'application`, `← Voltar à app`, `← Zurück zur App`],
    [`Come anonimizzare i dati sensibili prima di darli a un'AI e ripristinarli nella risposta.`]: [
      `How to anonymize sensitive data before giving it to an AI and restore it in the response.`,
      `Cómo anonimizar los datos sensibles antes de dárselos a una IA y restaurarlos en la respuesta.`,
      `Comment anonymiser les données sensibles avant de les donner à une IA et les restaurer dans la réponse.`,
      `Como anonimizar os dados sensíveis antes de os dar a uma IA e restaurá-los na resposta.`,
      `Wie Sie sensible Daten anonymisieren, bevor Sie sie einer KI geben, und sie in der Antwort wiederherstellen.`],
    [`A cosa serve`]: [`What it's for`, `Para qué sirve`, `À quoi ça sert`, `Para que serve`, `Wozu es dient`],
    [`pProxy sostituisce i dati sensibili (email, telefoni, IBAN, codici fiscali, nomi, indirizzi…) con <b>segnaposto</b> tipo <code>[EMAIL_001]</code>. Così puoi mandare il testo a un'AI senza esporre i dati reali; quando l'AI risponde (mantenendo i segnaposto), pProxy ricostruisce gli originali. La <b>mappa</b> segnaposto→valore reale è il dato più delicato: non viene mai inviata all'AI né scritta in chiaro.`]: [
      `pProxy replaces sensitive data (emails, phone numbers, IBANs, tax codes, names, addresses…) with <b>placeholders</b> like <code>[EMAIL_001]</code>. This way you can send the text to an AI without exposing the real data; when the AI responds (keeping the placeholders), pProxy rebuilds the originals. The <b>map</b> placeholder→real value is the most sensitive piece: it is never sent to the AI nor written in clear text.`,
      `pProxy sustituye los datos sensibles (correos, teléfonos, IBAN, códigos fiscales, nombres, direcciones…) por <b>marcadores</b> como <code>[EMAIL_001]</code>. Así puedes enviar el texto a una IA sin exponer los datos reales; cuando la IA responde (manteniendo los marcadores), pProxy reconstruye los originales. El <b>mapa</b> marcador→valor real es el dato más delicado: nunca se envía a la IA ni se escribe en claro.`,
      `pProxy remplace les données sensibles (e-mails, téléphones, IBAN, numéros fiscaux, noms, adresses…) par des <b>espaces réservés</b> comme <code>[EMAIL_001]</code>. Vous pouvez ainsi envoyer le texte à une IA sans exposer les données réelles ; lorsque l'IA répond (en conservant les espaces réservés), pProxy reconstruit les originaux. La <b>table</b> espace réservé→valeur réelle est la donnée la plus sensible : elle n'est jamais envoyée à l'IA ni écrite en clair.`,
      `O pProxy substitui os dados sensíveis (e-mails, telefones, IBAN, números fiscais, nomes, moradas…) por <b>marcadores</b> como <code>[EMAIL_001]</code>. Assim pode enviar o texto a uma IA sem expor os dados reais; quando a IA responde (mantendo os marcadores), o pProxy reconstrói os originais. O <b>mapa</b> marcador→valor real é o dado mais delicado: nunca é enviado à IA nem escrito em texto simples.`,
      `pProxy ersetzt sensible Daten (E-Mails, Telefonnummern, IBANs, Steuernummern, Namen, Adressen…) durch <b>Platzhalter</b> wie <code>[EMAIL_001]</code>. So können Sie den Text an eine KI senden, ohne die echten Daten preiszugeben; wenn die KI antwortet (und die Platzhalter beibehält), stellt pProxy die Originale wieder her. Die <b>Zuordnung</b> Platzhalter→echter Wert ist das sensibelste Datum: Sie wird niemals an die KI gesendet oder im Klartext gespeichert.`],
    [`I due modi di usarlo`]: [`The two ways to use it`, `Las dos formas de usarlo`, `Les deux façons de l'utiliser`, `As duas formas de o usar`, `Die zwei Nutzungsweisen`],
    [`A) Flusso manuale — usi la TUA AI (es. ChatGPT, Claude nel browser)`]: [
      `A) Manual flow — you use YOUR OWN AI (e.g. ChatGPT, Claude in the browser)`,
      `A) Flujo manual — usas TU propia IA (p. ej. ChatGPT, Claude en el navegador)`,
      `A) Flux manuel — vous utilisez VOTRE propre IA (ex. ChatGPT, Claude dans le navigateur)`,
      `A) Fluxo manual — usa a SUA própria IA (ex. ChatGPT, Claude no navegador)`,
      `A) Manueller Ablauf — Sie nutzen IHRE eigene KI (z. B. ChatGPT, Claude im Browser)`],
    [`<b>Anonimizza</b> (scheda 1): incolla il testo → <i>Anonimizza</i>. Ottieni il testo con i segnaposto e un <i>ID sessione</i>. Premi <i>Copia</i>.`]: [
      `<b>Anonymize</b> (tab 1): paste the text → <i>Anonymize</i>. You get the text with placeholders and a <i>session ID</i>. Press <i>Copy</i>.`,
      `<b>Anonimizar</b> (pestaña 1): pega el texto → <i>Anonimizar</i>. Obtienes el texto con marcadores y un <i>ID de sesión</i>. Pulsa <i>Copiar</i>.`,
      `<b>Anonymiser</b> (onglet 1) : collez le texte → <i>Anonymiser</i>. Vous obtenez le texte avec les espaces réservés et un <i>ID de session</i>. Appuyez sur <i>Copier</i>.`,
      `<b>Anonimizar</b> (separador 1): cole o texto → <i>Anonimizar</i>. Obtém o texto com os marcadores e um <i>ID de sessão</i>. Prima <i>Copiar</i>.`,
      `<b>Anonymisieren</b> (Reiter 1): Text einfügen → <i>Anonymisieren</i>. Sie erhalten den Text mit Platzhaltern und eine <i>Sitzungs-ID</i>. Drücken Sie <i>Kopieren</i>.`],
    [`Incolla quel testo nella tua AI e fatti dare la risposta. <b>Importante:</b> chiedi all'AI di <i>non modificare i segnaposto</i> <code>[…_NNN]</code>.`]: [
      `Paste that text into your AI and get its response. <b>Important:</b> ask the AI <i>not to modify the placeholders</i> <code>[…_NNN]</code>.`,
      `Pega ese texto en tu IA y obtén la respuesta. <b>Importante:</b> pide a la IA que <i>no modifique los marcadores</i> <code>[…_NNN]</code>.`,
      `Collez ce texte dans votre IA et obtenez la réponse. <b>Important :</b> demandez à l'IA de <i>ne pas modifier les espaces réservés</i> <code>[…_NNN]</code>.`,
      `Cole esse texto na sua IA e obtenha a resposta. <b>Importante:</b> peça à IA para <i>não modificar os marcadores</i> <code>[…_NNN]</code>.`,
      `Fügen Sie diesen Text in Ihre KI ein und holen Sie sich die Antwort. <b>Wichtig:</b> Bitten Sie die KI, <i>die Platzhalter nicht zu verändern</i> <code>[…_NNN]</code>.`],
    [`<b>Ripristina</b> (scheda 2): incolla la risposta dell'AI → <i>Ripristina dati originali</i>. L'ID sessione è già compilato. Ottieni il testo con i dati reali.`]: [
      `<b>Restore</b> (tab 2): paste the AI's response → <i>Restore original data</i>. The session ID is already filled in. You get the text with the real data.`,
      `<b>Restaurar</b> (pestaña 2): pega la respuesta de la IA → <i>Restaurar datos originales</i>. El ID de sesión ya está rellenado. Obtienes el texto con los datos reales.`,
      `<b>Restaurer</b> (onglet 2) : collez la réponse de l'IA → <i>Restaurer les données originales</i>. L'ID de session est déjà rempli. Vous obtenez le texte avec les données réelles.`,
      `<b>Restaurar</b> (separador 2): cole a resposta da IA → <i>Restaurar dados originais</i>. O ID de sessão já está preenchido. Obtém o texto com os dados reais.`,
      `<b>Wiederherstellen</b> (Reiter 2): Antwort der KI einfügen → <i>Originaldaten wiederherstellen</i>. Die Sitzungs-ID ist bereits ausgefüllt. Sie erhalten den Text mit den echten Daten.`],
    [`È il flusso che preserva di più la privacy: i dati reali non lasciano la tua macchina/il server verso l'AI. Con <b>Zero-knowledge</b> la mappa resta solo nel tuo browser (vedi sotto).`]: [
      `This is the most privacy-preserving flow: the real data never leaves your machine/the server toward the AI. With <b>Zero-knowledge</b> the map stays only in your browser (see below).`,
      `Es el flujo que más preserva la privacidad: los datos reales no salen de tu máquina/el servidor hacia la IA. Con <b>Zero-knowledge</b> el mapa permanece solo en tu navegador (ver abajo).`,
      `C'est le flux qui préserve le plus la confidentialité : les données réelles ne quittent pas votre machine/le serveur vers l'IA. Avec <b>Zero-knowledge</b>, la table reste uniquement dans votre navigateur (voir ci-dessous).`,
      `É o fluxo que mais preserva a privacidade: os dados reais não saem da sua máquina/do servidor para a IA. Com <b>Zero-knowledge</b> o mapa permanece apenas no seu navegador (ver abaixo).`,
      `Dies ist der datenschutzfreundlichste Ablauf: Die echten Daten verlassen Ihren Rechner/den Server nicht in Richtung KI. Mit <b>Zero-Knowledge</b> bleibt die Zuordnung nur in Ihrem Browser (siehe unten).`],
    [`B) Pipeline automatica — pProxy chiama l'AI al posto tuo`]: [
      `B) Automatic pipeline — pProxy calls the AI for you`,
      `B) Pipeline automática — pProxy llama a la IA en tu lugar`,
      `B) Pipeline automatique — pProxy appelle l'IA à votre place`,
      `B) Pipeline automática — o pProxy chama a IA por si`,
      `B) Automatische Pipeline — pProxy ruft die KI für Sie auf`],
    [`<b>Pipeline LLM</b> (scheda 3): incolla il testo o carica un file, scegli il <i>provider</i>.`]: [
      `<b>LLM pipeline</b> (tab 3): paste the text or upload a file, choose the <i>provider</i>.`,
      `<b>Pipeline LLM</b> (pestaña 3): pega el texto o sube un archivo, elige el <i>proveedor</i>.`,
      `<b>Pipeline LLM</b> (onglet 3) : collez le texte ou importez un fichier, choisissez le <i>fournisseur</i>.`,
      `<b>Pipeline LLM</b> (separador 3): cole o texto ou carregue um ficheiro, escolha o <i>fornecedor</i>.`,
      `<b>LLM-Pipeline</b> (Reiter 3): Text einfügen oder Datei hochladen, <i>Anbieter</i> wählen.`],
    [`Premi <i>Esegui pipeline</i>: pProxy anonimizza, invia all'AI (con la chiave API configurata sul server) e ti restituisce la risposta <b>già ripristinata</b>.`]: [
      `Press <i>Run pipeline</i>: pProxy anonymizes, sends it to the AI (with the API key configured on the server) and returns the <b>already-restored</b> response.`,
      `Pulsa <i>Ejecutar pipeline</i>: pProxy anonimiza, envía a la IA (con la clave API configurada en el servidor) y te devuelve la respuesta <b>ya restaurada</b>.`,
      `Appuyez sur <i>Exécuter la pipeline</i> : pProxy anonymise, envoie à l'IA (avec la clé API configurée sur le serveur) et vous renvoie la réponse <b>déjà restaurée</b>.`,
      `Prima <i>Executar pipeline</i>: o pProxy anonimiza, envia à IA (com a chave API configurada no servidor) e devolve-lhe a resposta <b>já restaurada</b>.`,
      `Drücken Sie <i>Pipeline ausführen</i>: pProxy anonymisiert, sendet an die KI (mit dem auf dem Server konfigurierten API-Schlüssel) und gibt Ihnen die <b>bereits wiederhergestellte</b> Antwort zurück.`],
    [`Usa il provider <code>demo</code> per provare senza chiave API. Per i provider reali (openai, anthropic, gemini, ollama) le chiavi si impostano lato server come variabili d'ambiente.`]: [
      `Use the <code>demo</code> provider to try without an API key. For real providers (openai, anthropic, gemini, ollama) the keys are set server-side as environment variables.`,
      `Usa el proveedor <code>demo</code> para probar sin clave API. Para los proveedores reales (openai, anthropic, gemini, ollama) las claves se configuran en el servidor como variables de entorno.`,
      `Utilisez le fournisseur <code>demo</code> pour essayer sans clé API. Pour les fournisseurs réels (openai, anthropic, gemini, ollama), les clés se définissent côté serveur comme variables d'environnement.`,
      `Use o fornecedor <code>demo</code> para experimentar sem chave API. Para os fornecedores reais (openai, anthropic, gemini, ollama), as chaves definem-se no servidor como variáveis de ambiente.`,
      `Nutzen Sie den Anbieter <code>demo</code>, um es ohne API-Schlüssel auszuprobieren. Für echte Anbieter (openai, anthropic, gemini, ollama) werden die Schlüssel serverseitig als Umgebungsvariablen gesetzt.`],
    [`Modalità zero-knowledge`]: [`Zero-knowledge mode`, `Modo zero-knowledge`, `Mode zero-knowledge`, `Modo zero-knowledge`, `Zero-Knowledge-Modus`],
    [`Se attivi <b>Zero-knowledge</b>, il server <b>non conserva nulla</b>: la mappa segnaposto→valore torna al tuo browser e viene usata lì per il ripristino. È l'opzione più riservata; lo svantaggio è che la mappa vive solo nella scheda corrente del browser (se ricarichi la pagina la perdi).`]: [
      `If you enable <b>Zero-knowledge</b>, the server <b>keeps nothing</b>: the placeholder→value map is returned to your browser and used there for restoration. It's the most private option; the drawback is that the map lives only in the current browser tab (if you reload the page you lose it).`,
      `Si activas <b>Zero-knowledge</b>, el servidor <b>no conserva nada</b>: el mapa marcador→valor vuelve a tu navegador y se usa ahí para la restauración. Es la opción más reservada; el inconveniente es que el mapa solo vive en la pestaña actual del navegador (si recargas la página lo pierdes).`,
      `Si vous activez <b>Zero-knowledge</b>, le serveur <b>ne conserve rien</b> : la table espace réservé→valeur revient dans votre navigateur et y est utilisée pour la restauration. C'est l'option la plus confidentielle ; l'inconvénient est que la table ne vit que dans l'onglet courant du navigateur (si vous rechargez la page, vous la perdez).`,
      `Se ativar <b>Zero-knowledge</b>, o servidor <b>não guarda nada</b>: o mapa marcador→valor volta ao seu navegador e é usado aí para a restauração. É a opção mais reservada; a desvantagem é que o mapa vive apenas no separador atual do navegador (se recarregar a página, perde-o).`,
      `Wenn Sie <b>Zero-Knowledge</b> aktivieren, <b>speichert der Server nichts</b>: Die Zuordnung Platzhalter→Wert wird an Ihren Browser zurückgegeben und dort für die Wiederherstellung verwendet. Es ist die vertraulichste Option; der Nachteil ist, dass die Zuordnung nur im aktuellen Browser-Tab existiert (beim Neuladen der Seite geht sie verloren).`],
    [`Le opzioni`]: [`The options`, `Las opciones`, `Les options`, `As opções`, `Die Optionen`],
    [`Opzione`]: [`Option`, `Opción`, `Option`, `Opção`, `Option`],
    [`Cosa fa`]: [`What it does`, `Qué hace`, `Ce que ça fait`, `O que faz`, `Funktion`],
    [`Soglia 0–1: più alta = meno falsi positivi, ma rischi di non rilevare qualcosa. Default 0.7.`]: [
      `Threshold 0–1: higher = fewer false positives, but you risk missing something. Default 0.7.`,
      `Umbral 0–1: más alto = menos falsos positivos, pero te arriesgas a no detectar algo. Predeterminado 0.7.`,
      `Seuil 0–1 : plus élevé = moins de faux positifs, mais vous risquez de ne pas détecter quelque chose. Par défaut 0.7.`,
      `Limiar 0–1: mais alto = menos falsos positivos, mas arrisca não detetar algo. Predefinição 0.7.`,
      `Schwelle 0–1: höher = weniger Fehlalarme, aber Sie riskieren, etwas zu übersehen. Standard 0.7.`],
    [`Limita il rilevamento ad alcuni tipi (es. <code>EMAIL,PHONE,CF</code>). Vuoto = tutti. Accetta anche le forme estese <code>ADDRESS</code>/<code>ORGANIZATION</code>/<code>LOCATION</code>.`]: [
      `Limits detection to certain types (e.g. <code>EMAIL,PHONE,CF</code>). Empty = all. It also accepts the extended forms <code>ADDRESS</code>/<code>ORGANIZATION</code>/<code>LOCATION</code>.`,
      `Limita la detección a ciertos tipos (p. ej. <code>EMAIL,PHONE,CF</code>). Vacío = todos. También acepta las formas extendidas <code>ADDRESS</code>/<code>ORGANIZATION</code>/<code>LOCATION</code>.`,
      `Limite la détection à certains types (ex. <code>EMAIL,PHONE,CF</code>). Vide = tous. Accepte aussi les formes étendues <code>ADDRESS</code>/<code>ORGANIZATION</code>/<code>LOCATION</code>.`,
      `Limita a deteção a certos tipos (ex. <code>EMAIL,PHONE,CF</code>). Vazio = todos. Também aceita as formas estendidas <code>ADDRESS</code>/<code>ORGANIZATION</code>/<code>LOCATION</code>.`,
      `Beschränkt die Erkennung auf bestimmte Typen (z. B. <code>EMAIL,PHONE,CF</code>). Leer = alle. Akzeptiert auch die ausführlichen Formen <code>ADDRESS</code>/<code>ORGANIZATION</code>/<code>LOCATION</code>.`],
    [`Abilita il riconoscimento di nomi/organizzazioni/luoghi via modelli (se installati sul server). Più lento.`]: [
      `Enables recognition of names/organizations/places via models (if installed on the server). Slower.`,
      `Habilita el reconocimiento de nombres/organizaciones/lugares mediante modelos (si están instalados en el servidor). Más lento.`,
      `Active la reconnaissance des noms/organisations/lieux via des modèles (s'ils sont installés sur le serveur). Plus lent.`,
      `Ativa o reconhecimento de nomes/organizações/locais através de modelos (se instalados no servidor). Mais lento.`,
      `Aktiviert die Erkennung von Namen/Organisationen/Orten über Modelle (falls auf dem Server installiert). Langsamer.`],
    [`Nella scheda Anonimizza, elenca anche i valori originali individuati (utile per verifica).`]: [
      `In the Anonymize tab, it also lists the original detected values (useful for verification).`,
      `En la pestaña Anonimizar, también lista los valores originales detectados (útil para verificación).`,
      `Dans l'onglet Anonymiser, liste aussi les valeurs originales détectées (utile pour vérification).`,
      `No separador Anonimizar, lista também os valores originais detetados (útil para verificação).`,
      `Im Reiter Anonymisieren werden auch die erkannten Originalwerte aufgelistet (nützlich zur Überprüfung).`],
    [`Pipeline: lunghezza massima dei blocchi per documenti lunghi. <code>0</code> = nessuna suddivisione.`]: [
      `Pipeline: maximum block length for long documents. <code>0</code> = no splitting.`,
      `Pipeline: longitud máxima de los bloques para documentos largos. <code>0</code> = sin división.`,
      `Pipeline : longueur maximale des blocs pour les longs documents. <code>0</code> = pas de découpage.`,
      `Pipeline: comprimento máximo dos blocos para documentos longos. <code>0</code> = sem divisão.`,
      `Pipeline: maximale Blocklänge für lange Dokumente. <code>0</code> = keine Aufteilung.`],
    [`Istruzione / System prompt`]: [`Instruction / System prompt`, `Instrucción / System prompt`, `Instruction / System prompt`, `Instrução / System prompt`, `Anweisung / System-Prompt`],
    [`Pipeline: il prompt dato all'AI. Usa <code>{document}</code> dove va inserito il testo anonimizzato.`]: [
      `Pipeline: the prompt given to the AI. Use <code>{document}</code> where the anonymized text should be inserted.`,
      `Pipeline: el prompt dado a la IA. Usa <code>{document}</code> donde se debe insertar el texto anonimizado.`,
      `Pipeline : le prompt donné à l'IA. Utilisez <code>{document}</code> à l'endroit où insérer le texte anonymisé.`,
      `Pipeline: o prompt dado à IA. Use <code>{document}</code> onde deve ser inserido o texto anonimizado.`,
      `Pipeline: der an die KI gegebene Prompt. Verwenden Sie <code>{document}</code> dort, wo der anonymisierte Text eingefügt werden soll.`],
    [`Ogni anonimizzazione (non zero-knowledge) crea una <b>sessione temporanea</b> sul server che custodisce la mappa, con scadenza automatica. L'<i>ID sessione</i> è una <b>credenziale</b>: chi lo conosce può ripristinare i dati — non condividerlo. Nella scheda <b>Sessioni</b> puoi verificarne lo stato o eliminarla subito.`]: [
      `Each anonymization (not zero-knowledge) creates a <b>temporary session</b> on the server that holds the map, with automatic expiration. The <i>session ID</i> is a <b>credential</b>: anyone who knows it can restore the data — don't share it. In the <b>Sessions</b> tab you can check its status or delete it immediately.`,
      `Cada anonimización (no zero-knowledge) crea una <b>sesión temporal</b> en el servidor que guarda el mapa, con caducidad automática. El <i>ID de sesión</i> es una <b>credencial</b>: quien lo conoce puede restaurar los datos — no lo compartas. En la pestaña <b>Sesiones</b> puedes comprobar su estado o eliminarla de inmediato.`,
      `Chaque anonymisation (hors zero-knowledge) crée une <b>session temporaire</b> sur le serveur qui conserve la table, avec expiration automatique. L'<i>ID de session</i> est un <b>identifiant</b> : quiconque le connaît peut restaurer les données — ne le partagez pas. Dans l'onglet <b>Sessions</b>, vous pouvez vérifier son état ou la supprimer immédiatement.`,
      `Cada anonimização (não zero-knowledge) cria uma <b>sessão temporária</b> no servidor que guarda o mapa, com expiração automática. O <i>ID de sessão</i> é uma <b>credencial</b>: quem o conhece pode restaurar os dados — não o partilhe. No separador <b>Sessões</b> pode verificar o seu estado ou eliminá-la de imediato.`,
      `Jede Anonymisierung (außer Zero-Knowledge) erstellt eine <b>temporäre Sitzung</b> auf dem Server, die die Zuordnung mit automatischem Ablauf verwahrt. Die <i>Sitzungs-ID</i> ist ein <b>Zugangsschlüssel</b>: Wer sie kennt, kann die Daten wiederherstellen — teilen Sie sie nicht. Im Reiter <b>Sitzungen</b> können Sie ihren Status prüfen oder sie sofort löschen.`],
    [`API key dell'app`]: [`App API key`, `Clave API de la app`, `Clé API de l'application`, `Chave API da app`, `API-Schlüssel der App`],
    [`Se l'operatore ha protetto il server con una API key, inseriscila nel campo <i>API key</i> in alto: verrà inviata come header <code>X-API-Key</code> con ogni richiesta.`]: [
      `If the operator has protected the server with an API key, enter it in the <i>API key</i> field at the top: it will be sent as the <code>X-API-Key</code> header with every request.`,
      `Si el operador ha protegido el servidor con una clave API, introdúcela en el campo <i>API key</i> de arriba: se enviará como cabecera <code>X-API-Key</code> en cada petición.`,
      `Si l'opérateur a protégé le serveur avec une clé API, saisissez-la dans le champ <i>API key</i> en haut : elle sera envoyée comme en-tête <code>X-API-Key</code> à chaque requête.`,
      `Se o operador protegeu o servidor com uma chave API, introduza-a no campo <i>API key</i> no topo: será enviada como cabeçalho <code>X-API-Key</code> em cada pedido.`,
      `Wenn der Betreiber den Server mit einem API-Schlüssel geschützt hat, geben Sie ihn oben im Feld <i>API key</i> ein: Er wird als Header <code>X-API-Key</code> mit jeder Anfrage gesendet.`],
    [`Tipi di dato riconosciuti`]: [`Recognized data types`, `Tipos de datos reconocidos`, `Types de données reconnus`, `Tipos de dados reconhecidos`, `Erkannte Datentypen`],
    [`PERSON, ORG, LOC, ADDR (indirizzo), EMAIL, PHONE, IBAN, CF (codice fiscale), PIVA, CARD (carta), DATE, AMOUNT (importo), CAP, ACCOUNT (conto). I codici con checksum (IBAN, CF, P.IVA, carte) sono validati per ridurre i falsi positivi.`]: [
      `PERSON, ORG, LOC, ADDR (address), EMAIL, PHONE, IBAN, CF (tax code), PIVA, CARD, DATE, AMOUNT, CAP (postal code), ACCOUNT. Codes with a checksum (IBAN, CF, P.IVA, cards) are validated to reduce false positives.`,
      `PERSON, ORG, LOC, ADDR (dirección), EMAIL, PHONE, IBAN, CF (código fiscal), PIVA, CARD (tarjeta), DATE, AMOUNT (importe), CAP (código postal), ACCOUNT (cuenta). Los códigos con checksum (IBAN, CF, P.IVA, tarjetas) se validan para reducir los falsos positivos.`,
      `PERSON, ORG, LOC, ADDR (adresse), EMAIL, PHONE, IBAN, CF (numéro fiscal), PIVA, CARD (carte), DATE, AMOUNT (montant), CAP (code postal), ACCOUNT (compte). Les codes à somme de contrôle (IBAN, CF, P.IVA, cartes) sont validés pour réduire les faux positifs.`,
      `PERSON, ORG, LOC, ADDR (morada), EMAIL, PHONE, IBAN, CF (número fiscal), PIVA, CARD (cartão), DATE, AMOUNT (montante), CAP (código postal), ACCOUNT (conta). Os códigos com checksum (IBAN, CF, P.IVA, cartões) são validados para reduzir os falsos positivos.`,
      `PERSON, ORG, LOC, ADDR (Adresse), EMAIL, PHONE, IBAN, CF (Steuernummer), PIVA, CARD (Karte), DATE, AMOUNT (Betrag), CAP (Postleitzahl), ACCOUNT (Konto). Codes mit Prüfsumme (IBAN, CF, P.IVA, Karten) werden validiert, um Fehlalarme zu reduzieren.`],
    [`Per chi usa l'API direttamente`]: [`For those using the API directly`, `Para quienes usan la API directamente`, `Pour ceux qui utilisent l'API directement`, `Para quem usa a API diretamente`, `Für alle, die die API direkt nutzen`],
    [`La documentazione interattiva degli endpoint è su <a href="/docs">/docs</a> (OpenAPI/Swagger). Endpoint principali: <code>POST /api/anonymize</code>, <code>POST /api/rehydrate</code>, <code>POST /api/process</code>, più le varianti <code>*-file</code> per gli upload e <code>GET/DELETE /api/session/{id}</code>.`]: [
      `The interactive endpoint documentation is at <a href="/docs">/docs</a> (OpenAPI/Swagger). Main endpoints: <code>POST /api/anonymize</code>, <code>POST /api/rehydrate</code>, <code>POST /api/process</code>, plus the <code>*-file</code> variants for uploads and <code>GET/DELETE /api/session/{id}</code>.`,
      `La documentación interactiva de los endpoints está en <a href="/docs">/docs</a> (OpenAPI/Swagger). Endpoints principales: <code>POST /api/anonymize</code>, <code>POST /api/rehydrate</code>, <code>POST /api/process</code>, además de las variantes <code>*-file</code> para las subidas y <code>GET/DELETE /api/session/{id}</code>.`,
      `La documentation interactive des endpoints est sur <a href="/docs">/docs</a> (OpenAPI/Swagger). Endpoints principaux : <code>POST /api/anonymize</code>, <code>POST /api/rehydrate</code>, <code>POST /api/process</code>, ainsi que les variantes <code>*-file</code> pour les imports et <code>GET/DELETE /api/session/{id}</code>.`,
      `A documentação interativa dos endpoints está em <a href="/docs">/docs</a> (OpenAPI/Swagger). Endpoints principais: <code>POST /api/anonymize</code>, <code>POST /api/rehydrate</code>, <code>POST /api/process</code>, além das variantes <code>*-file</code> para os carregamentos e <code>GET/DELETE /api/session/{id}</code>.`,
      `Die interaktive Endpoint-Dokumentation finden Sie unter <a href="/docs">/docs</a> (OpenAPI/Swagger). Haupt-Endpoints: <code>POST /api/anonymize</code>, <code>POST /api/rehydrate</code>, <code>POST /api/process</code>, zudem die <code>*-file</code>-Varianten für Uploads und <code>GET/DELETE /api/session/{id}</code>.`],

    // ---- app.js dynamic strings ----
    [`Copiato negli appunti.`]: [`Copied to clipboard.`, `Copiado al portapapeles.`, `Copié dans le presse-papiers.`, `Copiado para a área de transferência.`, `In die Zwischenablage kopiert.`],
    [`Copia non riuscita (usa Ctrl/Cmd+C).`]: [`Copy failed (use Ctrl/Cmd+C).`, `No se pudo copiar (usa Ctrl/Cmd+C).`, `Échec de la copie (utilisez Ctrl/Cmd+C).`, `Falha ao copiar (use Ctrl/Cmd+C).`, `Kopieren fehlgeschlagen (nutzen Sie Strg/Cmd+C).`],
    [`Errore`]: [`Error`, `Error`, `Erreur`, `Erro`, `Fehler`],
    [`Elaborazione…`]: [`Processing…`, `Procesando…`, `Traitement…`, `A processar…`, `Verarbeitung…`],
    [`Inserisci del testo o scegli un file.`]: [`Enter some text or choose a file.`, `Introduce texto o elige un archivo.`, `Saisissez du texte ou choisissez un fichier.`, `Introduza texto ou escolha um ficheiro.`, `Geben Sie Text ein oder wählen Sie eine Datei.`],
    [`entità`]: [`entities`, `entidades`, `entités`, `entidades`, `Entitäten`],
    [`validazione ✔`]: [`validation ✔`, `validación ✔`, `validation ✔`, `validação ✔`, `Validierung ✔`],
    [`validazione ✖`]: [`validation ✖`, `validación ✖`, `validation ✖`, `validação ✖`, `Validierung ✖`],
    [`zero-knowledge (mappa nel browser)`]: [`zero-knowledge (map in browser)`, `zero-knowledge (mapa en el navegador)`, `zero-knowledge (table dans le navigateur)`, `zero-knowledge (mapa no navegador)`, `Zero-Knowledge (Zuordnung im Browser)`],
    [`Fatto. Copia il testo, dallo alla tua AI, poi vai su «Ripristina».`]: [
      `Done. Copy the text, give it to your AI, then go to «Restore».`,
      `Hecho. Copia el texto, dáselo a tu IA y luego ve a «Restaurar».`,
      `Terminé. Copiez le texte, donnez-le à votre IA, puis allez dans « Restaurer ».`,
      `Concluído. Copie o texto, dê-o à sua IA e depois vá a «Restaurar».`,
      `Fertig. Kopieren Sie den Text, geben Sie ihn Ihrer KI und gehen Sie dann zu «Wiederherstellen».`],
    [`Incolla la risposta dell'AI.`]: [`Paste the AI's response.`, `Pega la respuesta de la IA.`, `Collez la réponse de l'IA.`, `Cole a resposta da IA.`, `Fügen Sie die Antwort der KI ein.`],
    [`Ripristino…`]: [`Restoring…`, `Restaurando…`, `Restauration…`, `A restaurar…`, `Wiederherstellung…`],
    [`Manca l'ID sessione.`]: [`The session ID is missing.`, `Falta el ID de sesión.`, `L'ID de session est manquant.`, `Falta o ID de sessão.`, `Die Sitzungs-ID fehlt.`],
    [`validazione ✖ (controlla i placeholder)`]: [`validation ✖ (check the placeholders)`, `validación ✖ (revisa los marcadores)`, `validation ✖ (vérifiez les espaces réservés)`, `validação ✖ (verifique os marcadores)`, `Validierung ✖ (Platzhalter prüfen)`],
    [`Fatto.`]: [`Done.`, `Hecho.`, `Terminé.`, `Concluído.`, `Fertig.`],
    [`Elaborazione (può richiedere qualche secondo)…`]: [`Processing (it may take a few seconds)…`, `Procesando (puede tardar unos segundos)…`, `Traitement (cela peut prendre quelques secondes)…`, `A processar (pode demorar alguns segundos)…`, `Verarbeitung (kann einige Sekunden dauern)…`],
    [`(non disponibile)`]: [`(not available)`, `(no disponible)`, `(non disponible)`, `(não disponível)`, `(nicht verfügbar)`],
    [`zero-knowledge / nessuna`]: [`zero-knowledge / none`, `zero-knowledge / ninguna`, `zero-knowledge / aucune`, `zero-knowledge / nenhuma`, `Zero-Knowledge / keine`],
    [`(ignorato dal demo)`]: [`(ignored by demo)`, `(ignorado por demo)`, `(ignoré par la démo)`, `(ignorado pelo demo)`, `(vom Demo ignoriert)`],
    [`Inserisci un ID sessione.`]: [`Enter a session ID.`, `Introduce un ID de sesión.`, `Saisissez un ID de session.`, `Introduza um ID de sessão.`, `Geben Sie eine Sitzungs-ID ein.`],
    [`Sessione eliminata.`]: [`Session deleted.`, `Sesión eliminada.`, `Session supprimée.`, `Sessão eliminada.`, `Sitzung gelöscht.`],
    [`attiva:`]: [`active:`, `activa:`, `active :`, `ativa:`, `aktiv:`],
    [`entità:`]: [`entities:`, `entidades:`, `entités :`, `entidades:`, `Entitäten:`],
    [`scade tra:`]: [`expires in:`, `caduca en:`, `expire dans :`, `expira em:`, `läuft ab in:`],
  };

  // ---- lookup tables ----
  const norm = (s) => s.replace(/\s+/g, " ").trim();
  const NORM = Object.create(null);
  for (const key in STRINGS) NORM[norm(key)] = STRINGS[key];

  function currentLang() {
    let l = null;
    try { l = localStorage.getItem(STORE_KEY); } catch (_) {}
    if (l && SUPPORTED.has(l)) return l;
    const nav = (navigator.language || "it").slice(0, 2).toLowerCase();
    return SUPPORTED.has(nav) ? nav : "it";
  }

  // Returns the translated string for the current language, the source itself
  // for Italian/unknown language, or null when the source is not a known key.
  function tr(src) {
    const arr = NORM[norm(src)];
    if (!arr) return null;
    const lang = currentLang();
    if (lang === "it") return src;
    const i = LANGS.indexOf(lang);
    return (i >= 0 && arr[i]) ? arr[i] : src;
  }

  // ---- DOM application ----
  const SRC = new WeakMap();   // element -> original innerHTML; text node -> original nodeValue
  const ATTR = new WeakMap();  // element -> original placeholder
  const SKIP = new Set(["SCRIPT", "STYLE"]);
  let TITLE_SRC = null;

  function srcHTML(el) { if (!SRC.has(el)) SRC.set(el, el.innerHTML); return SRC.get(el); }
  function srcText(n) { if (!SRC.has(n)) SRC.set(n, n.nodeValue); return SRC.get(n); }

  function applyTextNode(node) {
    const orig = srcText(node);
    const m = orig.match(/^(\s*)([\s\S]*?)(\s*)$/);
    if (!m[2]) return;
    const t = tr(m[2]);
    if (t === null) return;
    node.nodeValue = m[1] + t + m[3];
  }

  function walk(el) {
    if (SKIP.has(el.tagName)) return;
    if (el.tagName === "PRE" && el.classList.contains("ascii")) return;
    if (el.classList && el.classList.contains("lang-select")) return;
    const t = tr(srcHTML(el));
    if (t !== null) { el.innerHTML = t; return; }
    el.childNodes.forEach((node) => {
      if (node.nodeType === 1) walk(node);
      else if (node.nodeType === 3) applyTextNode(node);
    });
  }

  function applyAll() {
    walk(document.body);
    document.querySelectorAll("[placeholder]").forEach((el) => {
      if (!ATTR.has(el)) ATTR.set(el, el.getAttribute("placeholder"));
      const t = tr(ATTR.get(el));
      if (t !== null) el.setAttribute("placeholder", t);
    });
    if (TITLE_SRC === null) TITLE_SRC = document.title;
    const tt = tr(TITLE_SRC);
    if (tt !== null) document.title = tt;
    document.documentElement.lang = currentLang();
  }

  function buildSelector() {
    const bar = document.querySelector(".topbar");
    if (!bar) return;
    const wrap = document.createElement("div");
    wrap.className = "lang-wrap";
    wrap.style.cssText = "position:absolute;top:0;right:0;display:flex;gap:.5rem;align-items:center;";
    const sel = document.createElement("select");
    sel.className = "lang-select";
    sel.setAttribute("aria-label", "Language");
    sel.style.cssText = "font:inherit;padding:.25rem .4rem;border:1px solid var(--border);border-radius:6px;background:transparent;color:var(--fg);cursor:pointer;";
    LANGS_UI.forEach(([code, label]) => {
      const o = document.createElement("option");
      o.value = code; o.textContent = label;
      sel.appendChild(o);
    });
    sel.value = currentLang();
    sel.addEventListener("change", () => {
      try { localStorage.setItem(STORE_KEY, sel.value); } catch (_) {}
      applyAll();
    });
    wrap.appendChild(sel);
    const link = bar.querySelector(".guide-link");
    if (link) { link.style.position = "static"; wrap.appendChild(link); }
    bar.appendChild(wrap);
  }

  // Exposed for app.js dynamic strings.
  window.i18nT = function (s) { const t = tr(s); return t === null ? s : t; };

  function init() { buildSelector(); applyAll(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
