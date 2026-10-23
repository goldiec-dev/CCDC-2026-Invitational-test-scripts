# Injects and incident reports

## Submission rules (2026 MWCCDC team packet)
- **Submit a PDF** attached to the inject in the team portal (NISE). Other formats can't be read in the
  portal and may not be graded.
- **Never identify your school** - sign as "Team #" only (rule: requests must not identify the institution).
- Times in the portal are **CST**.
- A submission can be marked invalid and resubmitted while the inject is open, but resubmissions are limited.

## Writing a response
1. Copy the right template: `Blank Inject Template.docx` (general), `Blank Inject Network Template.docx`
   (firewall / network), `Blank Inject UM Template.docx` (management summary).
   Policies requested by an inject: start from `policies/` and fill in `[Company name]`, dates and approver.
2. Fill in: To / From (Team #) / Date / Subject `Inject #<n> - <title>`, executive summary, what was done
   (host + IP), and evidence (screenshots, command output - `linux/evidence.sh`, `windows/evidence.ps1`).
3. **Export to PDF:**
   - Word: File > Save As > PDF
   - LibreOffice: File > Export as PDF, or `soffice --headless --convert-to pdf "Inject 12.docx"`
4. Open the PDF and check it before uploading (images present, nothing cut off, no school name).

## Incident reports (10-20% of the score)
Report **exploitation events** (red team activity), not misconfigurations. Each report must contain:
- [ ] What happened, with **source and destination IP addresses**
- [ ] **Timeline** of the activity (times in CST)
- [ ] **Passwords cracked / accounts used**, if any
- [ ] What was affected (hosts, services, data)
- [ ] **Remediation plan** - what was done and what prevents a repeat
- [ ] Evidence: log lines, screenshots (the box `IR.md` "Record" step collects these)

Clear, thorough and accurate reports score best; frivolous or excessive reports can lose points.
