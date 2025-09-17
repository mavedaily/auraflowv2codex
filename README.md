# Aura Flow V2 — Professional SaaS Task & Team Manager

Aura Flow V2 is a professional SaaS-style web app for tasks, teams, and resources, built on **Google Apps Script** with a single-file **HTML/Tailwind** frontend.

---

## Features
- Secure login with salted+hashed passwords and session tokens
- Roles: Admin, Sub-Admin, Manager, Intern
- Task & Subtask CRUD, labels, resources, notes, due dates
- Assignment with hierarchy enforcement
- Kanban board with drag & drop
- Focus Mode timer with mood logging
- Dashboard metrics & analytics (Chart.js)
- Bulk upload (CSV/XLSX) with preview/validation
- CSV export & simple PDF report
- Activity log for auditing
- Optional Drive links & Calendar sync stubs
- Responsive, mobile-friendly UI with toasts and loading states

---

## Tech Stack
- **Backend:** Google Apps Script (`Code.gs`)
- **Frontend:** Single `index.html` (Tailwind CDN, Chart.js CDN, Vanilla JS)
- **Storage:** Google Sheets

---

## Quick Start
1. Open **Google Apps Script** → new project.
2. Create files:
   - `Code.gs` → paste from repo.
   - `index.html` → paste from repo.
3. Run `firstRunInit()` to create sheets & default admin.
4. **Deploy** → *Deploy as web app*  
   - Execute as: **Me**  
   - Who has access: **Anyone** (or your domain)
5. Open the web app URL → login (use the Admin created during `firstRunInit()`).

> If you prefer, you can also serve `index.html` via `HtmlService.createHtmlOutputFromFile('index')` inside `doGet()`.

---

## Sheets Schema
- **Users**: Email | PasswordHash | Salt | Role | ManagerEmail | IsActive | CreatedAt  
- **Tasks**: TaskID | Name | Category | Priority | Status | DurationMins | Labels | Notes | ResourcesCSV | Assigner | Assignee | Timestamp | DueAt | UpdatedAt | ParentTaskID  
- **Subtasks**: SubtaskID | TaskID | Name | DurationMins | Status | CreatedAt  
- **ActivityLog**: LogID | ActorEmail | Action | TargetType | TargetID | MetaJSON | At  
- **Moods**: EntryID | TaskID | Email | Mood | Note | At  
- **Attachments**: AttachmentID | TaskID | FileName | DriveId | Url | AddedBy | At

---

## Role Rules
- Admin → manage users; assign to anyone
- Sub-Admin → manage direct org below them
- Manager → assign only to interns
- Intern → self only

---

## Dev Tips
- Use `google.script.run.<fn>(...)` wrapped by a Promise proxy.
- Keep all JS in `index.html` to stay single-file.
- Validate inputs; show helpful toasts; keep login working.
- For PDF: HtmlService → PDF via Drive (see backend helper).

---

## Troubleshooting
- **Script function not found: doGet** → ensure `doGet(e)` exists in `Code.gs`.
- **Login does nothing** → check the frontend `server` proxy `.withSuccessHandler/.withFailureHandler`.
- **Headers missing** → re-run `firstRunInit()` or ensure header creation on first write.
- **Permission errors** → confirm roles and hierarchy fields in Users sheet.

---

## License
Proprietary — © Rare Aura Media Group
