"""Detect words that are neither Vietnamese nor English in the prose a planner model writes.

Small free models sometimes drop a word of another language into a Vietnamese sentence ("przeciwko", "tentativa",
"explotación", "ungewö"). Script filters already remove Chinese/Cyrillic/Arabic; this module covers Latin-script
languages, which no character range can separate from Vietnamese or English.

Method (no external data, no network):

1. a letter that exists in neither English nor Vietnamese (ö, ü, ñ, ç, ß, ł, ż, ...) is a certain hit;
2. a word that is a well-formed *Vietnamese syllable* (initial + vowel nucleus + final, tones ignored) is Vietnamese;
3. otherwise it must be English (a curated vocabulary of the words a hunting plan uses, with common inflections),
   or appear in the collected PoC/CVE text (``known``), or be an identifier/acronym/proper noun, else it is flagged.

It is a heuristic for a human-facing field, not a security control: a miss only leaves a stray word in the text,
and a false positive only costs one repair attempt, so it is used to ask the model to rewrite, never to drop a search.
"""
from __future__ import annotations

import re
import unicodedata

_VN_LETTERS = set("àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ")
_TONE_MARKS = {0x0300, 0x0301, 0x0303, 0x0309, 0x0323}
_VN_SYLLABLE = re.compile(
    r"^(?:ngh|ng|nh|ph|th|tr|ch|kh|gh|gi|qu|[bcdđghklmnpqrstvx])?[aăâeêioôơuưy]{1,3}(?:ch|ng|nh|[cmnpt])?$"
)
_EDGE = ".,;:!?()[]{}<>\u201c\u201d\"'\u2018\u2019\u2026\u2013\u2014*\u00ab\u00bb"
_IDENTIFIER = re.compile(r"[/\\._=:${}\[\]*|@#<>%&+~^0-9]")
_CODE = re.compile(r"`[^`]*`|https?://\S+")
_LETTERS = re.compile(r"[^\W\d_]+")
MIN_LETTERS = 4

# English the plans legitimately use (function words, hunting/IT vocabulary, product names). Lower-case; inflections
# (-s, -es, -ed, -ing, -ly, -er) are derived in code, so only base forms are listed.
_ENGLISH = """
a about above across action actions active activity actor actors add added after again against agent all allow allowed
almost along already also although always among an analysis analyst and any anything app application applications
apply are around as ask at attack attacker attacks attempt attempts authentication available
back bad base basic be because become been before behind being below benign between binary both browser brute build
but by call called can cannot case cases change changes check checks child chosen client clients close code command
common commonly compare compile complete compromise concern condition conditions configuration confirm connect
connection connections consider contain contains content context continue control copy core correct count create
credential credentials critical current custom data date day days default defender define delay delete deploy detail
details detect detection device did different directory discover discovery do does domain done down download drop
during each early effect either empty enable encode end endpoint enough entry environment error even event events every
evidence exact example execute execution exist exists expect expected exploit exposed external extract fail failed
failure false field fields file files filter find first flag follow following for force form found frame from full
function further future gain gap gateway general generic get give given go good group guess handle happen has have
hidden high history hit hits hold host hosts hour hours how however http identify if impact important in include
including indicate indicator indicators initial inject injection input inside instance instead internal into
investigate investigation is it its job just keep key kind know known large last late later launch layer lead least
leave legitimate less level like likely limit line link list live load local locate log logic login logs long look
low machine main make malicious manual many match may maybe mean means memory message method might minimum minute
minutes mismatch missing mode modify monitor more most move much must name names need network never new next no noise
noisy normal not note notes nothing now number observe observed of off often old on once one only open operation
or order origin other otherwise out outbound output over own packet page parameter parent part pass password path
pattern payload perform period persist pivot place plan please point policy port possible post power prefer present
previous primary probe problem process processes product production profile program property protocol provide proxy
public pull push query quick quite raw read real reason record recon reduce reference refer registry related relevant
remote remove repeat report request requests require required resource response restart restrict result results return
reverse review risk role rule run running safe same sample scan scanner scope script search second secret section
security see seen send sensitive sequence server service session set several severity shell short should show side
signal signature significant similar simple since single site size small so some source sources specific spike spawn
standard start state status step still stop store string strong structure subject success successful such suddenly
suggest suspicious system table take target team technique test text than that the their them then there these they
thing this those though threat three through time times to together token tool top total trace traffic trigger true
try type typical typically under unexpected unique unknown unless until up upload use used user users using usual
value values variable vendor verify version very via victim view visible visibility vulnerable wait want was watch
way we web well were what when where whether which while who why wide will window with within without work would
write written yet you your
abnormal administrator administrators admin anomaly approach archive artifact artifacts attacker's auth backdoor
beacon beaconing binding bypass cache callback certificate chain chmod cleanup cloud cluster collection compromised
config configure container cookie cron crontab cryptominer daemon dashboard decode decoy dependency deserialization
detail directory disable dropper dropped dump elevated email encoded encryption endpoint enumeration escalation
escape evasion exfiltration exploitation exploited extension false-positive firewall foothold framework gadget
gateway hash header headers hostname hunt hunting hunter hypothesis impersonation inbound incident ingress inventory
jar kernel lateral lookup malware metadata misconfiguration mitigation module mount obfuscated obfuscation
outbound overflow patch patched persistence phishing pipeline plugin post-exploitation privilege privileges
processes proof-of-concept reachable reconnaissance redirect regex remediation reverse-shell rollback runtime
sandbox scheduler sensitive shellcode signing spray stage stages staging stager telemetry template threshold
timestamp traversal tunnel unauthenticated unauthorised unauthorized unpatched update username utility
validation vulnerability vulnerabilities webshell whitelist wildcard workstation worm zero-day
apache nginx tomcat java javascript python perl ruby php bash powershell cmd curl wget netcat nc ssh sshd telnet ftp
smb rdp ldap ldaps rmi jndi dns http https tls ssl tcp udp icmp json xml yaml html base64 sql sqli xss csrf rce lfi
rfi ssrf xxe cve cwe cvss kev sysmon splunk windows linux unix macos ubuntu debian centos redhat docker kubernetes
spring springboot struts log4j log4shell joomla wordpress drupal exchange sharepoint confluence jenkins gitlab github
vmware citrix fortinet oracle weblogic jboss wildfly iis w3wp httpd php-fpm mysql postgres redis mongodb elasticsearch
war jsp jspx aspx asp dll exe sh bat cgi servlet classloader getshell cmdshell
whoami ipconfig ifconfig netstat tasklist systeminfo hostname uname nslookup dig ping traceroute certutil bitsadmin
mshta rundll32 regsvr32 wmic wmi schtasks sudo chown mkfifo openssl crontab systemctl service-account sh zsh dash ksh
debug debugging stacktrace stack exception handler listener controller bean mapping dispatcher endpoint-based parse parser logger
middleware framework library dependency gadget classpath bytecode reflection reflective lookup interpolation expression evaluation
wscript cscript msbuild installutil forfiles psexec mimikatz cobaltstrike metasploit meterpreter nmap masscan
""".split()
_MORE = """
adapter advisor assistant augmented automate backlog backoff band baseline basename branch breach caveat clean clone
closure commit concept confidence contract couple coverage critic decide decision declare deterministic disclose
disposition document driven edit engine escalate evaluate exfiltrate express extra final fix fixed fork fallback
guide human image index installation intelligence intensive intrusion judge judgment kept labour language ledger
literal localhost macro medium miss model multi offline operate optional parser placeholder practical predicate
principle produce project prompt proof prove rank rather recommend recommendation refine release repo research
researcher retrieval retry right schema sensor skip split stakeholder stream suit support thesis thousand
throughout traceback track transient twenty eight four five six seven nine ten unit unproven unstable wizard
abuse access accessible account accounts accurate achieve acquire activate actually address advanced affect agree
alert alias align alone alter alternative amount analyze annotate answer appear append approved argument arise arrive
assess asset assign assume attach attempted audit authorized automatic avoid aware balance based basis become begin
believe benefit beyond block body boundary bound branch break bridge broad budget bulk bundle business button
capture careful carry catch category cause cautious central certain challenge channel character charge choice
choose circumstance claim classify clear click close closely collect combine come comment communicate company
compare competing complex component compound compress concurrent conduct confident conflict connect consequence
consistent constant construct consume contact contrast contribute convert correlate cost cover crash credit
criteria cross culprit cycle damage dangerous decision declared decoded dedicated defeat defend deliver demand
demonstrate depend depth derive describe design desired destination detailed determine develop differ difficult
digital direct disable disconnect discard disk display distinct distribute divide drive due duplicate duration
dynamic easy effective efficient element embed emit encounter engineer ensure enter entire equal equivalent
establish estimate evaluate eventually evolve examine exception exchange exclude exhaust expand expensive expire
explain explicit explore export expose extend extent fact factor fall familiar fast feature feed field figure
fill final finding fine finish fire fit fix flow focus force forget format forward fragment free frequent
friendly front fully gather generate genuine global goal grant guard guess handler happen hard hardware hide
highlight honest hope however human idea ignore illegal immediate impossible improve incomplete increase
independent indirect individual inform infrastructure inherit inspect install intent interact interest interface
interpret interval introduce invalid invoke involve isolate issue item itself keyword label lack language leak
learn legal length lesson letter library lift light limited location lock logical loss maintain major manage
manner margin mark material matter maximum measure mechanism member mention merge minor mirror misuse mix
modern monitoring multiple narrow native nearly necessary neither network nobody normally notice notification
object obtain obvious occur offer official online operator opposite option organization original outcome
outside overall overview owner package pair partial particular partner passive past peak peer people percent
permanent permission person physical pick piece plain platform popular position positive potential practice
precise predict prepare pressure prevent principal print priority private probably procedure produce progress
promise proper protect proven public purpose quality quantity question quickly range rare rather reach react
ready realistic recent recognize recover recurring redundant region register regular reject relate release
reliable remain remote rename repeated replace reply represent reproduce request reserve reset resolve respond
restore restrict retain reveal revert rich rough route routine rely safely satisfy save scale schedule screen
seem select sense sequence serve setting settle shape share shift shortly shown sign silent simply situation
skill slow smart software solution solve somewhat sort space speak special speed spend stable stand startup
static stay store straight strategy strict strictly strongly study style subtle suffer sufficient suggest
suitable summary supply surface survive switch symptom target technical temporary term terminate thin
threshold tiny together tolerate topic touch trace trade train transfer transform transit treat trend trick
trust turn typical ultimately unable unclear understand unfortunately unlikely unnecessary unusual upgrade
urgent usage useful usually valid vary verbose violate virtual visit volume warn weak website weight whole
widely wrong yield
""".split()
ENGLISH = frozenset(w for w in (*_ENGLISH, *_MORE) if w)

_SUFFIXES = (("ies", "y"), ("es", ""), ("s", ""), ("ed", ""), ("ed", "e"), ("d", ""), ("ing", ""), ("ing", "e"),
             ("ly", ""), ("ally", ""), ("er", ""), ("er", "e"), ("ers", ""), ("est", ""), ("ness", ""), ("ment", ""),
             ("ments", ""), ("ion", "e"), ("ions", "e"), ("ation", "e"), ("ations", "e"), ("ity", ""), ("al", ""))


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _strip_tones(word: str) -> str:
    decomposed = unicodedata.normalize("NFD", word.lower())
    return unicodedata.normalize("NFC", "".join(c for c in decomposed if ord(c) not in _TONE_MARKS))


def is_vietnamese_syllable(word: str) -> bool:
    return bool(_VN_SYLLABLE.match(_strip_tones(word)))


def is_english(word: str) -> bool:
    w = word.lower()
    if w in ENGLISH:
        return True
    for suffix, repl in _SUFFIXES:
        if w.endswith(suffix) and len(w) - len(suffix) >= 3:
            stem = w[: -len(suffix)] + repl
            if stem in ENGLISH:
                return True
            if len(stem) >= 4 and stem[-1] == stem[-2] and stem[:-1] in ENGLISH:  # running -> run
                return True
    return False


def vocabulary(*texts: str) -> frozenset[str]:
    """Lower-case words (3+ letters) of the collected PoC/CVE text: whatever the sources themselves say is not foreign."""
    found: set[str] = set()
    for text in texts:
        found.update(w.lower() for w in _LETTERS.findall(_nfc(text or "")) if len(w) >= 3)
    return frozenset(found)


def _candidates(text: str):
    cleaned = _CODE.sub(" ", _nfc(text or ""))
    for chunk in cleaned.split():
        chunk = chunk.strip(_EDGE)
        if not chunk or _IDENTIFIER.search(chunk):
            continue
        for part in re.split(r"[-\u2013\u2014'\u2019]", chunk):
            part = part.strip(_EDGE)
            if part and part.isalpha():
                yield part


def foreign_words(text: str, known: frozenset[str] | set[str] = frozenset()) -> list[str]:
    """Words of ``text`` that are neither Vietnamese nor English (see module docstring), in order, without repeats."""
    flagged: list[str] = []
    for word in _candidates(text):
        if len(word) < MIN_LETTERS and not any(c.isalpha() and c.lower() not in _VN_LETTERS and not ("a" <= c.lower() <= "z") for c in word):
            continue
        if word.isupper() or word[0].isupper() or any(c.isupper() for c in word[1:]):
            continue  # acronym, proper noun or identifier
        lowered = word.lower()
        outsider = any(c not in _VN_LETTERS and not ("a" <= c <= "z") for c in lowered)
        if not outsider:
            if is_vietnamese_syllable(lowered) or lowered in known or is_english(lowered):
                continue
        if word not in flagged:
            flagged.append(word)
    return flagged
