var SHEET_NAMES = {
  USERS: 'Users',
  TASKS: 'Tasks',
  SUBTASKS: 'Subtasks',
  ACTIVITY_LOG: 'ActivityLog',
  MOODS: 'Moods',
  ATTACHMENTS: 'Attachments'
};

var SHEET_HEADERS = {};
SHEET_HEADERS[SHEET_NAMES.USERS] = [
  'Email',
  'PasswordHash',
  'Salt',
  'Role',
  'ManagerEmail',
  'IsActive',
  'CreatedAt'
];
SHEET_HEADERS[SHEET_NAMES.TASKS] = [
  'TaskID',
  'Name',
  'Category',
  'Priority',
  'Status',
  'DurationMins',
  'Labels',
  'Notes',
  'ResourcesCSV',
  'Assigner',
  'Assignee',
  'Timestamp',
  'DueAt',
  'UpdatedAt',
  'ParentTaskID'
];
SHEET_HEADERS[SHEET_NAMES.SUBTASKS] = [
  'SubtaskID',
  'TaskID',
  'Name',
  'DurationMins',
  'Status',
  'CreatedAt'
];
SHEET_HEADERS[SHEET_NAMES.ACTIVITY_LOG] = [
  'LogID',
  'ActorEmail',
  'Action',
  'TargetType',
  'TargetID',
  'MetaJSON',
  'At'
];
SHEET_HEADERS[SHEET_NAMES.MOODS] = [
  'EntryID',
  'TaskID',
  'Email',
  'Mood',
  'Note',
  'At'
];
SHEET_HEADERS[SHEET_NAMES.ATTACHMENTS] = [
  'AttachmentID',
  'TaskID',
  'FileName',
  'DriveId',
  'Url',
  'AddedBy',
  'At'
];

var ROLE_RANK = {
  'Admin': 4,
  'Sub-Admin': 3,
  'Manager': 2,
  'Intern': 1
};

var ROLE_PERMISSIONS = {
  'Admin': ['*', 'users:manage', 'users:view', 'tasks:manage', 'tasks:view', 'reports:generate', 'moods:view', 'moods:log', 'sessions:manage'],
  'Sub-Admin': ['users:view', 'tasks:manage', 'tasks:view', 'moods:log', 'moods:view'],
  'Manager': ['users:view', 'tasks:manage:team', 'tasks:view', 'moods:log'],
  'Intern': ['tasks:view:self', 'tasks:manage:self', 'moods:log']
};

var SESSION_CACHE_PREFIX = 'afv2_session_';
var SESSION_USER_INDEX_PREFIX = 'afv2_session_idx_';
var SESSION_TTL_SECONDS = 6 * 60 * 60; // 6 hours
var DEFAULT_ADMIN_PASSWORD = 'ChangeMeNow!1';

function doGet(e) {
  firstRunInit();
  return HtmlService
    .createHtmlOutputFromFile('index')
    .setTitle('Aura Flow V2')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function login(email, password) {
  return handleApi_(function () {
    var normalizedEmail = normalizeEmail_(requireNonEmptyString_(email, 'Email'));
    var providedPassword = requireNonEmptyString_(password, 'Password', { trim: false });
    firstRunInit();
    var userResult = getUserByEmail_(normalizedEmail);
    if (!userResult) {
      throw new Error('Invalid credentials.');
    }
    var user = userResult.record;
    if (!isTrue_(user.IsActive)) {
      throw new Error('Account is disabled.');
    }
    if (!user.Salt || !user.PasswordHash) {
      throw new Error('Account is not properly configured.');
    }
    var expected = user.PasswordHash;
    var providedHash = hashPassword_(providedPassword, user.Salt);
    if (expected !== providedHash) {
      throw new Error('Invalid credentials.');
    }
    var session = createSessionForUser_(user);
    logActivity_(user.Email, 'login', 'User', user.Email, {});
    return {
      token: session.token,
      user: session.user
    };
  });
}

function logout(token) {
  return handleApi_(function () {
    var sessionToken = token ? String(token).trim() : '';
    if (sessionToken) {
      var session = getSession_(sessionToken);
      if (session) {
        logActivity_(session.email, 'logout', 'User', session.email, {});
      }
      destroySession_(sessionToken);
    }
    return true;
  });
}

function whoami(token) {
  return handleApi_(function () {
    var session = requireSession_(token);
    return {
      token: session.token,
      user: session.user
    };
  });
}

function listUsers(token) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'users:view');
    var sheet = ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.USERS];
    var users = sheetObjects_(sheet, headers).map(function (row) {
      return sanitizeUser_(row);
    });
    return users;
  });
}

function upsertUser(token, userObj) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'users:manage');
    if (!userObj || typeof userObj !== 'object') {
      throw new Error('User object is required.');
    }
    var emailInput = requireNonEmptyString_(userObj.Email, 'Email');
    var normalizedEmail = normalizeEmail_(emailInput);
    var desiredRole = String(userObj.Role || 'Intern').trim() || 'Intern';
    if (!ROLE_RANK[desiredRole]) {
      throw new Error('Invalid role.');
    }
    var managerEmail = normalizeEmail_(userObj.ManagerEmail);
    var sheet = ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.USERS];
    var userResult = getUserByEmail_(normalizedEmail);
    var now = nowIso_();
    var isActiveValue = userObj.IsActive === false || String(userObj.IsActive).toUpperCase() === 'FALSE' ? 'FALSE' : 'TRUE';
    if (userResult) {
      var record = userResult.record;
      var originalRole = record.Role || 'Intern';
      record.Email = normalizedEmail;
      record.Role = desiredRole;
      record.ManagerEmail = managerEmail;
      record.IsActive = isActiveValue;
      if (userObj.Password) {
        var passwordValue = requireNonEmptyString_(userObj.Password, 'Password', { trim: false });
        var salt = generateSalt_();
        record.Salt = salt;
        record.PasswordHash = hashPassword_(passwordValue, salt);
      }
      writeRow_(sheet, headers, userResult.rowNumber, record);
      if ((ROLE_RANK[originalRole] || 0) > (ROLE_RANK[record.Role] || 0) || !isTrue_(record.IsActive)) {
        invalidateSessionsForUser_(record.Email);
      }
      logActivity_(session, 'user.update', 'User', record.Email, {});
      return sanitizeUser_(record);
    }
    var passwordNew = requireNonEmptyString_(userObj.Password, 'Password', { trim: false });
    var saltNew = generateSalt_();
    var newRecord = {
      Email: normalizedEmail,
      PasswordHash: hashPassword_(passwordNew, saltNew),
      Salt: saltNew,
      Role: desiredRole,
      ManagerEmail: managerEmail,
      IsActive: isActiveValue,
      CreatedAt: now
    };
    appendRow_(sheet, headers, newRecord);
    logActivity_(session, 'user.create', 'User', normalizedEmail, {});
    if (!isTrue_(newRecord.IsActive)) {
      invalidateSessionsForUser_(newRecord.Email);
    }
    return sanitizeUser_(newRecord);
  });
}

function disableUser(token, email) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'users:manage');
    var normalizedEmail = normalizeEmail_(requireNonEmptyString_(email, 'Email'));
    var userResult = getUserByEmail_(normalizedEmail);
    if (!userResult) {
      throw new Error('User not found.');
    }
    var record = userResult.record;
    record.Email = normalizedEmail;
    record.IsActive = 'FALSE';
    writeRow_(ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]), SHEET_HEADERS[SHEET_NAMES.USERS], userResult.rowNumber, record);
    invalidateSessionsForUser_(record.Email);
    logActivity_(session, 'user.disable', 'User', record.Email, {});
    return sanitizeUser_(record);
  });
}

function resetUserPassword(token, email, newPassword) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!session || (session.role || (session.user && session.user.Role)) !== 'Admin') {
      throw new Error('Admins only.');
    }
    var normalizedEmail = normalizeEmail_(requireNonEmptyString_(email, 'Email'));
    var passwordValue = requireNonEmptyString_(newPassword, 'New password', { trim: false });
    var userResult = getUserByEmail_(normalizedEmail);
    if (!userResult) {
      throw new Error('User not found.');
    }
    var record = userResult.record;
    record.Email = normalizedEmail;
    var salt = generateSalt_();
    record.Salt = salt;
    record.PasswordHash = hashPassword_(passwordValue, salt);
    writeRow_(ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]), SHEET_HEADERS[SHEET_NAMES.USERS], userResult.rowNumber, record);
    invalidateSessionsForUser_(record.Email);
    logActivity_(session, 'user.resetPassword', 'User', record.Email, {});
    return sanitizeUser_(record);
  });
}

function refreshSession(token) {
  return handleApi_(function () {
    var session = requireSession_(token);
    persistSession_(session);
    return {
      token: session.token,
      user: session.user,
      refreshedAt: session.lastSeenAt
    };
  });
}

function assignTask(token, taskId, assigneeEmail) {
  return handleApi_(function () {
    var session = requireSession_(token);
    var canManageAll = hasPermission_(session, 'tasks:manage');
    var canManageTeam = hasPermission_(session, 'tasks:manage:team');
    var canManageSelf = hasPermission_(session, 'tasks:manage:self');
    if (!canManageAll && !canManageTeam && !canManageSelf) {
      throw new Error('Forbidden.');
    }
    var normalizedTaskId = requireNonEmptyString_(taskId, 'Task ID');
    var normalizedAssignee = normalizeEmail_(requireNonEmptyString_(assigneeEmail, 'Assignee email'));
    if (canManageSelf && !canManageAll && !canManageTeam) {
      if (!session.user || session.user.Email !== normalizedAssignee) {
        throw new Error('You can only assign tasks to yourself.');
      }
    }
    var assigneeResult = ensureActiveUserRecord_(normalizedAssignee, 'Assignee must be an active user.');
    var taskResult = getTaskById_(normalizedTaskId);
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.TASKS];
    var record = taskResult.record;
    record.TaskID = record.TaskID || normalizedTaskId;
    record.Assignee = normalizeEmail_(assigneeResult.record.Email) || normalizedAssignee;
    record.Assigner = session.user ? session.user.Email : normalizeEmail_(session.email);
    record.UpdatedAt = nowIso_();
    writeRow_(sheet, headers, taskResult.rowNumber, record);
    logActivity_(session, 'task.assign', 'Task', record.TaskID, {
      assignee: record.Assignee,
      assigner: record.Assigner
    });
    return record;
  });
}

function logMood(token, entry) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'moods:log');
    if (!entry || typeof entry !== 'object') {
      throw new Error('Mood entry is required.');
    }
    var moodValue = requireNonEmptyString_(entry.Mood, 'Mood');
    var taskId = requireNonEmptyString_(entry.TaskID, 'Task ID');
    var taskResult = getTaskById_(taskId);
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.MOODS, SHEET_HEADERS[SHEET_NAMES.MOODS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.MOODS];
    var record = {
      EntryID: generateId_('MOOD'),
      TaskID: taskResult.record.TaskID,
      Email: session.user ? session.user.Email : normalizeEmail_(session.email),
      Mood: moodValue,
      Note: entry.Note ? String(entry.Note).trim() : '',
      At: nowIso_()
    };
    appendRow_(sheet, headers, record);
    logActivity_(session, 'mood.log', 'Task', taskResult.record.TaskID, {
      mood: moodValue
    });
    return record;
  });
}

function firstRunInit() {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000);
  } catch (err) {
    throw new Error('System busy. Please retry.');
  }
  try {
    var ss = SpreadsheetApp.getActive();
    if (!ss) {
      throw new Error('No active spreadsheet found.');
    }
    for (var key in SHEET_NAMES) {
      if (SHEET_NAMES.hasOwnProperty(key)) {
        ensureSheet_(SHEET_NAMES[key], SHEET_HEADERS[SHEET_NAMES[key]]);
      }
    }
    ensureDefaultAdmin_();
  } finally {
    lock.releaseLock();
  }
}

function ensureDefaultAdmin_() {
  var sheet = ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.USERS];
  var rows = sheetObjects_(sheet, headers);
  var hasActiveAdmin = false;
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (String(row.Role).toLowerCase() === 'admin' && isTrue_(row.IsActive)) {
      hasActiveAdmin = true;
      break;
    }
  }
  if (hasActiveAdmin) {
    return;
  }
  var activeEmail = '';
  try {
    activeEmail = Session.getActiveUser().getEmail();
  } catch (err) {
    activeEmail = '';
  }
  var defaultEmail = normalizeEmail_(activeEmail || 'admin@example.com') || 'admin@example.com';
  var existing = getUserByEmail_(defaultEmail);
  if (existing) {
    var existingRecord = existing.record;
    existingRecord.Email = defaultEmail;
    existingRecord.Role = 'Admin';
    existingRecord.IsActive = 'TRUE';
    if (!existingRecord.PasswordHash || !existingRecord.Salt) {
      var saltExisting = generateSalt_();
      existingRecord.Salt = saltExisting;
      existingRecord.PasswordHash = hashPassword_(DEFAULT_ADMIN_PASSWORD, saltExisting);
    }
    writeRow_(sheet, headers, existing.rowNumber, existingRecord);
    logActivity_('system', 'bootstrap.admin.promote', 'User', defaultEmail, {});
    return;
  }
  var saltNew = generateSalt_();
  var record = {
    Email: defaultEmail,
    PasswordHash: hashPassword_(DEFAULT_ADMIN_PASSWORD, saltNew),
    Salt: saltNew,
    Role: 'Admin',
    ManagerEmail: '',
    IsActive: 'TRUE',
    CreatedAt: nowIso_()
  };
  appendRow_(sheet, headers, record);
  logActivity_('system', 'bootstrap.admin.create', 'User', defaultEmail, {});
}

function ensureSheet_(name, headers) {
  var ss = SpreadsheetApp.getActive();
  var sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
  }
  if (headers && headers.length) {
    var existingHeaders = sheet.getRange(1, 1, 1, sheet.getMaxColumns()).getValues()[0];
    var needsReset = false;
    for (var i = 0; i < headers.length; i++) {
      if (existingHeaders[i] !== headers[i]) {
        needsReset = true;
        break;
      }
    }
    if (needsReset || sheet.getLastRow() === 0) {
      sheet.clearContents();
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    }
  }
  return sheet;
}

function sheetObjects_(sheet, headers) {
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return [];
  }
  var range = sheet.getRange(2, 1, lastRow - 1, headers.length);
  var values = range.getValues();
  var objects = [];
  for (var i = 0; i < values.length; i++) {
    var obj = arrayToObject_(headers, values[i]);
    obj._rowNumber = i + 2;
    objects.push(obj);
  }
  return objects;
}

function arrayToObject_(headers, row) {
  var obj = {};
  for (var i = 0; i < headers.length; i++) {
    obj[headers[i]] = row[i];
  }
  return obj;
}

function writeRow_(sheet, headers, rowNumber, record) {
  var rowValues = [];
  for (var i = 0; i < headers.length; i++) {
    var key = headers[i];
    rowValues.push(record[key] !== undefined ? record[key] : '');
  }
  sheet.getRange(rowNumber, 1, 1, headers.length).setValues([rowValues]);
}

function appendRow_(sheet, headers, record) {
  var rowValues = [];
  for (var i = 0; i < headers.length; i++) {
    var key = headers[i];
    rowValues.push(record[key] !== undefined ? record[key] : '');
  }
  sheet.appendRow(rowValues);
}

function getUserByEmail_(email) {
  var normalized = normalizeEmail_(email);
  if (!normalized) {
    return null;
  }
  var sheet = ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.USERS];
  var emailIndex = headers.indexOf('Email');
  if (emailIndex === -1) {
    throw new Error('Users sheet missing Email column.');
  }
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return null;
  }
  var range = sheet.getRange(2, 1, lastRow - 1, headers.length);
  var values = range.getValues();
  for (var i = 0; i < values.length; i++) {
    var rowValue = values[i];
    var rowEmail = normalizeEmail_(rowValue[emailIndex]);
    if (rowEmail === normalized) {
      var record = arrayToObject_(headers, rowValue);
      record.Email = normalized;
      record.ManagerEmail = normalizeEmail_(record.ManagerEmail);
      return {
        rowNumber: i + 2,
        record: record
      };
    }
  }
  return null;
}

function getTaskById_(taskId) {
  if (taskId === null || taskId === undefined) {
    return null;
  }
  var normalizedId = String(taskId).trim();
  if (!normalizedId) {
    return null;
  }
  var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.TASKS];
  var idIndex = headers.indexOf('TaskID');
  if (idIndex === -1) {
    throw new Error('Tasks sheet missing TaskID column.');
  }
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return null;
  }
  var range = sheet.getRange(2, 1, lastRow - 1, headers.length);
  var values = range.getValues();
  for (var i = 0; i < values.length; i++) {
    var row = values[i];
    var currentId = String(row[idIndex] || '').trim();
    if (currentId === normalizedId) {
      var record = arrayToObject_(headers, row);
      record.TaskID = currentId;
      record.Assignee = normalizeEmail_(record.Assignee);
      record.Assigner = normalizeEmail_(record.Assigner);
      return {
        rowNumber: i + 2,
        record: record
      };
    }
  }
  return null;
}

function sanitizeUser_(record) {
  if (!record) {
    return null;
  }
  return {
    Email: normalizeEmail_(record.Email),
    Role: record.Role || 'Intern',
    ManagerEmail: normalizeEmail_(record.ManagerEmail || ''),
    IsActive: isTrue_(record.IsActive),
    CreatedAt: record.CreatedAt || ''
  };
}

function isTrue_(value) {
  return value === true || String(value).toUpperCase() === 'TRUE';
}

function hashPassword_(password, salt) {
  if (!salt) {
    throw new Error('Missing password salt.');
  }
  var passwordString = password === null || password === undefined ? '' : String(password);
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + '::' + passwordString);
  return Utilities.base64Encode(digest);
}

function generateSalt_() {
  return Utilities.base64EncodeWebSafe(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, Utilities.getUuid()));
}

function createSessionForUser_(userRecord) {
  if (!userRecord || !userRecord.Email) {
    throw new Error('Cannot create session for unknown user.');
  }
  var now = nowIso_();
  var session = {
    token: generateId_('SESS'),
    email: normalizeEmail_(userRecord.Email),
    role: userRecord.Role || 'Intern',
    createdAt: now,
    lastSeenAt: now
  };
  persistSession_(session);
  session.user = sanitizeUser_(userRecord);
  return session;
}

function persistSession_(session) {
  if (!session || !session.token) {
    return;
  }
  var cache = CacheService.getScriptCache();
  var normalizedEmail = normalizeEmail_(session.email);
  var now = nowIso_();
  session.email = normalizedEmail;
  session.lastSeenAt = now;
  var payload = safeStringify_({
    token: session.token,
    email: normalizedEmail,
    role: session.role || 'Intern',
    createdAt: session.createdAt || now,
    lastSeenAt: session.lastSeenAt
  });
  cache.put(SESSION_CACHE_PREFIX + session.token, payload, SESSION_TTL_SECONDS);
  if (normalizedEmail) {
    upsertSessionIndex_(normalizedEmail, session.token);
  }
}

function destroySession_(token) {
  if (!token) {
    return;
  }
  var cache = CacheService.getScriptCache();
  var payload = cache.get(SESSION_CACHE_PREFIX + token);
  if (payload) {
    var data = safeParse_(payload, null);
    if (data && data.email) {
      removeTokenFromUserIndex_(data.email, token);
    }
  }
  cache.remove(SESSION_CACHE_PREFIX + token);
}

function getSession_(token) {
  if (!token) {
    return null;
  }
  var sessionToken = String(token).trim();
  if (!sessionToken) {
    return null;
  }
  var cache = CacheService.getScriptCache();
  var payload = cache.get(SESSION_CACHE_PREFIX + sessionToken);
  if (!payload) {
    return null;
  }
  var base = safeParse_(payload, null);
  if (!base || !base.email) {
    destroySession_(sessionToken);
    return null;
  }
  var userResult = getUserByEmail_(base.email);
  if (!userResult) {
    destroySession_(sessionToken);
    return null;
  }
  var record = userResult.record;
  if (!isTrue_(record.IsActive)) {
    invalidateSessionsForUser_(record.Email);
    return null;
  }
  var actualRole = record.Role || 'Intern';
  var cachedRole = base.role || actualRole;
  var actualRank = ROLE_RANK[actualRole] || 0;
  var cachedRank = ROLE_RANK[cachedRole] || 0;
  if (actualRank < cachedRank) {
    invalidateSessionsForUser_(record.Email);
    return null;
  }
  base.role = actualRole;
  base.email = normalizeEmail_(record.Email);
  base.user = sanitizeUser_(record);
  base.token = sessionToken;
  base.createdAt = base.createdAt || nowIso_();
  persistSession_(base);
  return base;
}

function requireSession_(token) {
  var sessionToken = token ? String(token).trim() : '';
  if (!sessionToken) {
    throw new Error('Unauthorized.');
  }
  var session = getSession_(sessionToken);
  if (!session) {
    throw new Error('Unauthorized.');
  }
  return session;
}

function hasPermission_(session, perm) {
  if (!session) {
    return false;
  }
  var role = session.role || (session.user && session.user.Role) || 'Intern';
  var permissions = ROLE_PERMISSIONS[role] || [];
  if (permissions.indexOf('*') !== -1) {
    return true;
  }
  return permissions.indexOf(perm) !== -1;
}

function ensurePermission_(session, perm) {
  if (!session) {
    throw new Error('Unauthorized.');
  }
  if (!hasPermission_(session, perm)) {
    throw new Error('Forbidden.');
  }
  return true;
}

function logActivity_(sessionOrEmail, action, targetType, targetId, meta) {
  try {
    var sheet = ensureSheet_(SHEET_NAMES.ACTIVITY_LOG, SHEET_HEADERS[SHEET_NAMES.ACTIVITY_LOG]);
    var actorEmail = '';
    if (sessionOrEmail) {
      if (typeof sessionOrEmail === 'string') {
        actorEmail = normalizeEmail_(sessionOrEmail);
      } else if (sessionOrEmail.email) {
        actorEmail = normalizeEmail_(sessionOrEmail.email);
      } else if (sessionOrEmail.user && sessionOrEmail.user.Email) {
        actorEmail = normalizeEmail_(sessionOrEmail.user.Email);
      }
    }
    var record = {
      LogID: generateId_('LOG'),
      ActorEmail: actorEmail,
      Action: action || '',
      TargetType: targetType || '',
      TargetID: targetId || '',
      MetaJSON: safeStringify_(meta || {}),
      At: nowIso_()
    };
    appendRow_(sheet, SHEET_HEADERS[SHEET_NAMES.ACTIVITY_LOG], record);
  } catch (err) {
    Logger.log('Failed to log activity: ' + err);
  }
}

function nowIso_() {
  return new Date().toISOString();
}

function handleApi_(callback) {
  try {
    var data = callback();
    return {
      success: true,
      data: data === undefined ? null : data
    };
  } catch (err) {
    Logger.log('API error: ' + (err && err.stack ? err.stack : err));
    return {
      success: false,
      error: err && err.message ? err.message : String(err)
    };
  }
}

function safeParse_(payload, fallback) {
  try {
    if (payload === null || payload === undefined || payload === '') {
      return fallback;
    }
    return JSON.parse(payload);
  } catch (err) {
    return fallback;
  }
}

function safeStringify_(value) {
  try {
    return JSON.stringify(value || {});
  } catch (err) {
    return '{}';
  }
}

function generateId_(prefix) {
  var raw = Utilities.getUuid().replace(/-/g, '');
  return prefix ? prefix + '_' + raw : raw;
}

function normalizeEmail_(email) {
  if (email === null || email === undefined) {
    return '';
  }
  return String(email).trim().toLowerCase();
}

function requireNonEmptyString_(value, fieldName, options) {
  if (value === null || value === undefined) {
    throw new Error(fieldName + ' is required.');
  }
  var str = String(value);
  if (!options || options.trim !== false) {
    str = str.trim();
  }
  if (!str) {
    throw new Error(fieldName + ' is required.');
  }
  return str;
}

function ensureActiveUserRecord_(email, errorMessage) {
  var normalized = normalizeEmail_(email);
  if (!normalized) {
    throw new Error(errorMessage || 'User must be active.');
  }
  var userResult = getUserByEmail_(normalized);
  if (!userResult || !isTrue_(userResult.record.IsActive)) {
    throw new Error(errorMessage || 'User must be active.');
  }
  userResult.record.Email = normalized;
  return userResult;
}

function upsertSessionIndex_(email, token) {
  if (!email || !token) {
    return;
  }
  var cache = CacheService.getScriptCache();
  var key = SESSION_USER_INDEX_PREFIX + email;
  var payload = cache.get(key);
  var tokens = payload ? safeParse_(payload, []) : [];
  if (tokens.indexOf(token) === -1) {
    tokens.push(token);
  }
  cache.put(key, safeStringify_(tokens), SESSION_TTL_SECONDS);
}

function removeTokenFromUserIndex_(email, token) {
  if (!email || !token) {
    return;
  }
  var cache = CacheService.getScriptCache();
  var key = SESSION_USER_INDEX_PREFIX + email;
  var payload = cache.get(key);
  if (!payload) {
    return;
  }
  var tokens = safeParse_(payload, []);
  var filtered = [];
  for (var i = 0; i < tokens.length; i++) {
    if (tokens[i] && tokens[i] !== token) {
      filtered.push(tokens[i]);
    }
  }
  if (filtered.length) {
    cache.put(key, safeStringify_(filtered), SESSION_TTL_SECONDS);
  } else {
    cache.remove(key);
  }
}

function invalidateSessionsForUser_(email) {
  var normalized = normalizeEmail_(email);
  if (!normalized) {
    return;
  }
  var cache = CacheService.getScriptCache();
  var key = SESSION_USER_INDEX_PREFIX + normalized;
  var payload = cache.get(key);
  if (!payload) {
    return;
  }
  cache.remove(key);
  var tokens = safeParse_(payload, []);
  for (var i = 0; i < tokens.length; i++) {
    if (tokens[i]) {
      destroySession_(tokens[i]);
    }
  }
}
