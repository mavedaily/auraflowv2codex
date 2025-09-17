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

var TASK_STATUSES = ['Planned', 'In-Progress', 'Completed', 'Shifted', 'Cancelled'];

var SESSION_CACHE_PREFIX = 'afv2_session_';
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
    if (!email || !password) {
      throw new Error('Email and password are required.');
    }
    firstRunInit();
    var userResult = getUserByEmail_(email);
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
    var provided = hashPassword_(password, user.Salt);
    if (expected !== provided) {
      throw new Error('Invalid credentials.');
    }
    var session = createSessionForUser_(user);
    logActivity_(user.Email, 'login', 'User', user.Email, {});
    return {
      token: session.token,
      user: sanitizeUser_(user)
    };
  });
}

function logout(token) {
  return handleApi_(function () {
    if (token) {
      var session = getSession_(token);
      if (session) {
        logActivity_(session.email, 'logout', 'User', session.email, {});
      }
      destroySession_(token);
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
    if (!userObj || !userObj.Email) {
      throw new Error('Email is required.');
    }
    var email = String(userObj.Email).trim();
    if (!email) {
      throw new Error('Email is required.');
    }
    var normalizedEmail = email.toLowerCase();
    var desiredRole = userObj.Role || 'Intern';
    if (!ROLE_RANK[desiredRole]) {
      throw new Error('Invalid role.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.USERS];
    var userResult = getUserByEmail_(normalizedEmail);
    var now = nowIso_();
    if (userResult) {
      var record = userResult.record;
      record.Email = email;
      record.Role = desiredRole;
      record.ManagerEmail = userObj.ManagerEmail || '';
      record.IsActive = userObj.IsActive === false || userObj.IsActive === 'FALSE' ? 'FALSE' : 'TRUE';
      if (userObj.Password) {
        var salt = generateSalt_();
        record.Salt = salt;
        record.PasswordHash = hashPassword_(userObj.Password, salt);
      }
      writeRow_(sheet, headers, userResult.rowNumber, record);
      logActivity_(session, 'user.update', 'User', record.Email, {});
      return sanitizeUser_(record);
    }
    if (!userObj.Password) {
      throw new Error('Password is required for new users.');
    }
    var saltNew = generateSalt_();
    var newRecord = {
      Email: email,
      PasswordHash: hashPassword_(userObj.Password, saltNew),
      Salt: saltNew,
      Role: desiredRole,
      ManagerEmail: userObj.ManagerEmail || '',
      IsActive: userObj.IsActive === false || userObj.IsActive === 'FALSE' ? 'FALSE' : 'TRUE',
      CreatedAt: now
    };
    appendRow_(sheet, headers, newRecord);
    logActivity_(session, 'user.create', 'User', email, {});
    return sanitizeUser_(newRecord);
  });
}

function disableUser(token, email) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'users:manage');
    if (!email) {
      throw new Error('Email is required.');
    }
    var userResult = getUserByEmail_((email));
    if (!userResult) {
      throw new Error('User not found.');
    }
    var record = userResult.record;
    record.IsActive = 'FALSE';
    writeRow_(ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]), SHEET_HEADERS[SHEET_NAMES.USERS], userResult.rowNumber, record);
    logActivity_(session, 'user.disable', 'User', record.Email, {});
    return sanitizeUser_(record);
  });
}

function listTasks(token, filters) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!sessionHasPermission_(session, 'tasks:view') && !sessionHasPermission_(session, 'tasks:view:self')) {
      throw new Error('Forbidden.');
    }
    var usersMap = loadUsersMap_();
    var normalizedFilters = normalizeTaskFilters_(filters);
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.TASKS];
    var rows = sheetObjects_(sheet, headers);
    var results = [];
    for (var i = 0; i < rows.length; i++) {
      var record = rows[i];
      if (!canViewTask_(session, record, usersMap)) {
        continue;
      }
      if (!taskMatchesFilters_(record, normalizedFilters)) {
        continue;
      }
      results.push(record);
    }
    results.sort(function (a, b) {
      var aKey = a.UpdatedAt || a.Timestamp || '';
      var bKey = b.UpdatedAt || b.Timestamp || '';
      if (aKey === bKey) {
        return 0;
      }
      return aKey < bKey ? 1 : -1;
    });
    var total = results.length;
    var start = normalizedFilters.cursor;
    var end = Math.min(start + normalizedFilters.limit, total);
    var slice = [];
    for (var j = start; j < end; j++) {
      slice.push(sanitizeTask_(results[j]));
    }
    return {
      items: slice,
      nextCursor: end < total ? String(end) : null,
      total: total
    };
  });
}

function getTask(token, id) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!id) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(id);
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canViewTask_(session, taskResult.record, usersMap)) {
      throw new Error('Forbidden.');
    }
    var sanitized = sanitizeTask_(taskResult.record);
    sanitized.Subtasks = getSubtasksForTask_(taskResult.record.TaskID).map(function (row) {
      return sanitizeSubtask_(row);
    });
    return sanitized;
  });
}

function upsertTask(token, taskObj) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!sessionHasPermission_(session, 'tasks:manage') && !sessionHasPermission_(session, 'tasks:manage:team') && !sessionHasPermission_(session, 'tasks:manage:self')) {
      throw new Error('Forbidden.');
    }
    var payload = typeof taskObj === 'string' ? safeParse_(taskObj, null) : taskObj;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Task payload is required.');
    }
    if (payload.taskId && !payload.TaskID) {
      payload.TaskID = payload.taskId;
    }
    var isUpdate = Boolean(payload.TaskID);
    var usersMap = loadUsersMap_();
    var sessionEmail = session.user && session.user.Email ? session.user.Email : session.email || '';
    var nameValue = pickFirstDefined_(payload, ['Name', 'name']);
    var trimmedName = nameValue !== undefined && nameValue !== null ? String(nameValue).trim() : '';
    var assigneeValue = pickFirstDefined_(payload, ['Assignee', 'assignee']);
    var assigneeNormalized = assigneeValue ? normalizeEmail_(assigneeValue) : '';
    var assigneeRecord = assigneeNormalized ? usersMap[assigneeNormalized] : null;
    if (assigneeNormalized && !assigneeRecord) {
      throw new Error('Assignee not found.');
    }
    if (assigneeRecord && !isTrue_(assigneeRecord.IsActive)) {
      throw new Error('Assignee is disabled.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.TASKS];
    var now = nowIso_();
    if (!isUpdate && !trimmedName) {
      throw new Error('Task name is required.');
    }
    if (isUpdate) {
      var existing = getTaskById_(payload.TaskID);
      if (!existing) {
        throw new Error('Task not found.');
      }
      var record = existing.record;
      var targetAssignee = record.Assignee;
      if (assigneeValue !== undefined) {
        targetAssignee = assigneeRecord ? assigneeRecord.Email : String(assigneeValue || '');
      }
      if (!canManageTask_(session, record, targetAssignee, usersMap)) {
        throw new Error('Forbidden.');
      }
      if (trimmedName) {
        record.Name = trimmedName;
      }
      var categoryValue = pickFirstDefined_(payload, ['Category', 'category']);
      if (categoryValue !== undefined) {
        record.Category = String(categoryValue || '');
      }
      var priorityValue = pickFirstDefined_(payload, ['Priority', 'priority']);
      if (priorityValue !== undefined) {
        record.Priority = String(priorityValue || '');
      }
      var statusValue = pickFirstDefined_(payload, ['Status', 'status']);
      if (statusValue !== undefined) {
        record.Status = normalizeStatus_(statusValue);
      }
      var durationValue = pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']);
      if (durationValue !== undefined) {
        record.DurationMins = normalizeDuration_(durationValue, record.DurationMins);
      }
      var labelsValue = pickFirstDefined_(payload, ['Labels', 'labels']);
      if (labelsValue !== undefined) {
        record.Labels = toCsvString_(labelsValue);
      }
      var notesValue = pickFirstDefined_(payload, ['Notes', 'notes']);
      if (notesValue !== undefined) {
        record.Notes = String(notesValue || '');
      }
      var resourcesValue = pickFirstDefined_(payload, ['ResourcesCSV', 'resourcesCSV', 'Resources', 'resources']);
      if (resourcesValue !== undefined) {
        record.ResourcesCSV = toCsvString_(resourcesValue);
      }
      if (assigneeValue !== undefined) {
        record.Assignee = assigneeRecord ? assigneeRecord.Email : String(assigneeValue || '');
      }
      var dueValue = pickFirstDefined_(payload, ['DueAt', 'dueAt', 'DueDate', 'dueDate']);
      if (dueValue !== undefined) {
        record.DueAt = dueValue ? String(dueValue) : '';
      }
      var parentValue = pickFirstDefined_(payload, ['ParentTaskID', 'parentTaskId', 'ParentID', 'parentId']);
      if (parentValue !== undefined) {
        record.ParentTaskID = parentValue ? String(parentValue) : '';
      }
      record.UpdatedAt = now;
      writeRow_(sheet, headers, existing.rowNumber, record);
      logActivity_(session, 'task.update', 'Task', record.TaskID, { status: record.Status, assignee: record.Assignee });
      return sanitizeTask_(record);
    }
    var newRecord = {
      TaskID: payload.TaskID || generateId_('TASK'),
      Name: trimmedName || 'Untitled Task',
      Category: String(pickFirstDefined_(payload, ['Category', 'category']) || ''),
      Priority: String(pickFirstDefined_(payload, ['Priority', 'priority']) || ''),
      Status: normalizeStatus_(pickFirstDefined_(payload, ['Status', 'status']) || 'Planned'),
      DurationMins: normalizeDuration_(pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']), 0),
      Labels: toCsvString_(pickFirstDefined_(payload, ['Labels', 'labels'])),
      Notes: String(pickFirstDefined_(payload, ['Notes', 'notes']) || ''),
      ResourcesCSV: toCsvString_(pickFirstDefined_(payload, ['ResourcesCSV', 'resourcesCSV', 'Resources', 'resources'])),
      Assigner: sessionEmail,
      Assignee: '',
      Timestamp: now,
      DueAt: String(pickFirstDefined_(payload, ['DueAt', 'dueAt', 'DueDate', 'dueDate']) || ''),
      UpdatedAt: now,
      ParentTaskID: String(pickFirstDefined_(payload, ['ParentTaskID', 'parentTaskId', 'ParentID', 'parentId']) || '')
    };
    if (assigneeRecord) {
      newRecord.Assignee = assigneeRecord.Email;
    } else if (assigneeValue) {
      newRecord.Assignee = String(assigneeValue || '');
    } else if (sessionHasPermission_(session, 'tasks:manage:self') && !sessionHasPermission_(session, 'tasks:manage:team') && !sessionHasPermission_(session, 'tasks:manage')) {
      newRecord.Assignee = sessionEmail;
    }
    if (!canManageTask_(session, newRecord, newRecord.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    appendRow_(sheet, headers, newRecord);
    logActivity_(session, 'task.create', 'Task', newRecord.TaskID, { status: newRecord.Status, assignee: newRecord.Assignee });
    return sanitizeTask_(newRecord);
  });
}

function deleteTask(token, id) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!id) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(id);
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    sheet.deleteRow(taskResult.rowNumber);
    deleteSubtasksForTask_(id);
    logActivity_(session, 'task.delete', 'Task', id, {});
    return true;
  });
}

function listSubtasks(token, taskId) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!taskId) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_((taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canViewTask_(session, taskResult.record, usersMap)) {
      throw new Error('Forbidden.');
    }
    return getSubtasksForTask_(taskResult.record.TaskID).map(function (row) {
      return sanitizeSubtask_(row);
    });
  });
}

function upsertSubtask(token, subtaskObj) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!sessionHasPermission_(session, 'tasks:manage') && !sessionHasPermission_(session, 'tasks:manage:team') && !sessionHasPermission_(session, 'tasks:manage:self')) {
      throw new Error('Forbidden.');
    }
    var payload = typeof subtaskObj === 'string' ? safeParse_(subtaskObj, null) : subtaskObj;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Subtask payload is required.');
    }
    if (payload.subtaskId && !payload.SubtaskID) {
      payload.SubtaskID = payload.subtaskId;
    }
    if (payload.taskId && !payload.TaskID) {
      payload.TaskID = payload.taskId;
    }
    if (!payload.TaskID) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(payload.TaskID);
    if (!taskResult) {
      throw new Error('Parent task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
    var headers = SHEET_HEADERS[SHEET_NAMES.SUBTASKS];
    var now = nowIso_();
    var nameValue = pickFirstDefined_(payload, ['Name', 'name']);
    var trimmedName = nameValue !== undefined && nameValue !== null ? String(nameValue).trim() : '';
    var statusValue = pickFirstDefined_(payload, ['Status', 'status']);
    var durationValue = pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']);
    if (payload.SubtaskID) {
      var existing = getSubtaskById_(payload.SubtaskID);
      if (!existing) {
        throw new Error('Subtask not found.');
      }
      existing.record.TaskID = taskResult.record.TaskID;
      var record = existing.record;
      if (trimmedName) {
        record.Name = trimmedName;
      }
      if (durationValue !== undefined) {
        record.DurationMins = normalizeDuration_(durationValue, record.DurationMins);
      }
      if (statusValue !== undefined) {
        record.Status = normalizeStatus_(statusValue);
      }
      writeRow_(sheet, headers, existing.rowNumber, record);
      logActivity_(session, 'subtask.update', 'Subtask', record.SubtaskID, { taskId: record.TaskID, status: record.Status });
      return sanitizeSubtask_(record);
    }
    var newRecord = {
      SubtaskID: payload.SubtaskID || generateId_('SUBTASK'),
      TaskID: taskResult.record.TaskID,
      Name: trimmedName || 'Untitled Subtask',
      DurationMins: normalizeDuration_(durationValue, 0),
      Status: normalizeStatus_(statusValue || 'Planned'),
      CreatedAt: now
    };
    appendRow_(sheet, headers, newRecord);
    logActivity_(session, 'subtask.create', 'Subtask', newRecord.SubtaskID, { taskId: newRecord.TaskID, status: newRecord.Status });
    return sanitizeSubtask_(newRecord);
  });
}

function deleteSubtask(token, subtaskId) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!subtaskId) {
      throw new Error('Subtask ID is required.');
    }
    var existing = getSubtaskById_(subtaskId);
    if (!existing) {
      throw new Error('Subtask not found.');
    }
    var taskResult = getTaskById_(existing.record.TaskID);
    if (!taskResult) {
      throw new Error('Parent task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
    sheet.deleteRow(existing.rowNumber);
    logActivity_(session, 'subtask.delete', 'Subtask', existing.record.SubtaskID, { taskId: existing.record.TaskID });
    return true;
  });
}

function setTaskStatus(token, id, status) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!id) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(id);
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
  if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
    throw new Error('Forbidden.');
  }
  if (status === undefined || status === null) {
    throw new Error('Status is required.');
  }
  var normalizedStatus = normalizeStatus_(status);
  var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
  var record = taskResult.record;
  record.Status = normalizedStatus;
  record.UpdatedAt = nowIso_();
    writeRow_(sheet, SHEET_HEADERS[SHEET_NAMES.TASKS], taskResult.rowNumber, record);
    logActivity_(session, 'task.status', 'Task', record.TaskID, { status: normalizedStatus });
    return sanitizeTask_(record);
  });
}

function logMood(token, taskId, mood, note) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'moods:log');
    var moodValue = mood !== undefined && mood !== null ? String(mood).trim() : '';
    if (!moodValue) {
      throw new Error('Mood is required.');
    }
    var normalizedTaskId = taskId ? String(taskId) : '';
    if (normalizedTaskId) {
      var taskResult = getTaskById_(normalizedTaskId);
      if (!taskResult) {
        throw new Error('Task not found.');
      }
      var usersMap = loadUsersMap_();
      if (!canViewTask_(session, taskResult.record, usersMap)) {
        throw new Error('Forbidden.');
      }
    }
    var sheet = ensureSheet_(SHEET_NAMES.MOODS, SHEET_HEADERS[SHEET_NAMES.MOODS]);
    var record = {
      EntryID: generateId_('MOOD'),
      TaskID: normalizedTaskId,
      Email: session.user && session.user.Email ? session.user.Email : session.email || '',
      Mood: moodValue,
      Note: note !== undefined && note !== null ? String(note) : '',
      At: nowIso_()
    };
    appendRow_(sheet, SHEET_HEADERS[SHEET_NAMES.MOODS], record);
    logActivity_(session, 'mood.log', 'Task', normalizedTaskId, { mood: moodValue });
    return sanitizeMood_(record);
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
  var defaultEmail = activeEmail || 'admin@example.com';
  var existing = getUserByEmail_(defaultEmail);
  if (existing) {
    var existingRecord = existing.record;
    existingRecord.Role = 'Admin';
    existingRecord.IsActive = 'TRUE';
    if (!existingRecord.PasswordHash || !existingRecord.Salt) {
      var salt = generateSalt_();
      existingRecord.Salt = salt;
      existingRecord.PasswordHash = hashPassword_(DEFAULT_ADMIN_PASSWORD, salt);
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
    var rowEmail = normalizeEmail_(rowValue[emailIndex] || '');
    if (rowEmail === normalized) {
      return {
        rowNumber: i + 2,
        record: arrayToObject_(headers, rowValue)
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
    Email: record.Email,
    Role: record.Role,
    ManagerEmail: record.ManagerEmail || '',
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
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + '::' + password);
  return Utilities.base64Encode(digest);
}

function generateSalt_() {
  return Utilities.base64EncodeWebSafe(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, Utilities.getUuid()));
}

function createSessionForUser_(userRecord) {
  var token = generateId_('SESS');
  var session = {
    token: token,
    email: userRecord.Email,
    role: userRecord.Role || 'Intern',
    createdAt: nowIso_()
  };
  persistSession_(session);
  session.user = sanitizeUser_(userRecord);
  return session;
}

function persistSession_(session) {
  var cache = CacheService.getScriptCache();
  var payload = safeStringify_({
    token: session.token,
    email: session.email,
    role: session.role,
    createdAt: session.createdAt
  });
  cache.put(SESSION_CACHE_PREFIX + session.token, payload, SESSION_TTL_SECONDS);
}

function destroySession_(token) {
  if (!token) {
    return;
  }
  CacheService.getScriptCache().remove(SESSION_CACHE_PREFIX + token);
}

function getSession_(token) {
  if (!token) {
    return null;
  }
  var cache = CacheService.getScriptCache();
  var payload = cache.get(SESSION_CACHE_PREFIX + token);
  if (!payload) {
    return null;
  }
  var base = safeParse_(payload, null);
  if (!base) {
    return null;
  }
  var userResult = getUserByEmail_(base.email);
  if (!userResult) {
    return null;
  }
  var record = userResult.record;
  if (!isTrue_(record.IsActive)) {
    return null;
  }
  base.role = record.Role || base.role || 'Intern';
  base.user = sanitizeUser_(record);
  persistSession_(base);
  return base;
}

function requireSession_(token) {
  var session = getSession_(token);
  if (!session) {
    throw new Error('Unauthorized.');
  }
  return session;
}

function sessionHasPermission_(session, perm) {
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
  if (!sessionHasPermission_(session, perm)) {
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
        actorEmail = sessionOrEmail;
      } else if (sessionOrEmail.email) {
        actorEmail = sessionOrEmail.email;
      } else if (sessionOrEmail.user && sessionOrEmail.user.Email) {
        actorEmail = sessionOrEmail.user.Email;
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
      data: data
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

function pickFirstDefined_(obj, keys) {
  if (!obj) {
    return undefined;
  }
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (obj.hasOwnProperty(key) && obj[key] !== undefined && obj[key] !== null) {
      return obj[key];
    }
  }
  return undefined;
}

function normalizeEmail_(email) {
  if (email === null || email === undefined) {
    return '';
  }
  var value = String(email).trim().toLowerCase();
  return value;
}

function loadUsersMap_() {
  var sheet = ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.USERS];
  var rows = sheetObjects_(sheet, headers);
  var map = {};
  for (var i = 0; i < rows.length; i++) {
    var email = normalizeEmail_(rows[i].Email);
    if (email) {
      map[email] = rows[i];
    }
  }
  return map;
}

function canManageUser_(session, targetEmail, usersMap) {
  var normalizedTarget = normalizeEmail_(targetEmail);
  if (!normalizedTarget) {
    return true;
  }
  var sessionEmail = normalizeEmail_(session && (session.email || (session.user && session.user.Email)));
  if (!sessionEmail) {
    return false;
  }
  if (normalizedTarget === sessionEmail) {
    return true;
  }
  if (sessionHasPermission_(session, 'tasks:manage')) {
    return true;
  }
  if (!sessionHasPermission_(session, 'tasks:manage:team')) {
    return false;
  }
  var users = usersMap || {};
  var target = users[normalizedTarget];
  if (!target) {
    return false;
  }
  var sessionRoleRank = ROLE_RANK[session.role] || ROLE_RANK['Intern'];
  var targetRoleRank = ROLE_RANK[target.Role] || ROLE_RANK['Intern'];
  if (sessionRoleRank <= targetRoleRank) {
    return false;
  }
  var manager = normalizeEmail_(target.ManagerEmail);
  while (manager) {
    if (manager === sessionEmail) {
      return true;
    }
    var next = users[manager];
    if (!next) {
      break;
    }
    manager = normalizeEmail_(next.ManagerEmail);
  }
  return false;
}

function canManageTask_(session, taskRecord, newAssignee, usersMap) {
  if (!session) {
    return false;
  }
  var sessionEmail = normalizeEmail_(session.email || (session.user && session.user.Email));
  if (!sessionEmail) {
    return false;
  }
  if (sessionHasPermission_(session, 'tasks:manage')) {
    return true;
  }
  var assigneeEmail = normalizeEmail_(newAssignee !== undefined ? newAssignee : (taskRecord && taskRecord.Assignee));
  var assignerEmail = taskRecord ? normalizeEmail_(taskRecord.Assigner) : '';
  if (sessionHasPermission_(session, 'tasks:manage:team')) {
    if (assigneeEmail) {
      if (assigneeEmail === sessionEmail || canManageUser_(session, assigneeEmail, usersMap)) {
        return true;
      }
    } else {
      return true;
    }
    if (assignerEmail && (assignerEmail === sessionEmail || canManageUser_(session, assignerEmail, usersMap))) {
      return true;
    }
  }
  if (sessionHasPermission_(session, 'tasks:manage:self')) {
    if (assigneeEmail && assigneeEmail === sessionEmail) {
      return true;
    }
    if (assignerEmail && assignerEmail === sessionEmail) {
      return true;
    }
  }
  return false;
}

function canViewTask_(session, taskRecord, usersMap) {
  if (!taskRecord) {
    return false;
  }
  if (sessionHasPermission_(session, 'tasks:manage')) {
    return true;
  }
  var sessionEmail = normalizeEmail_(session && (session.email || (session.user && session.user.Email)));
  var assigneeEmail = normalizeEmail_(taskRecord.Assignee);
  var assignerEmail = normalizeEmail_(taskRecord.Assigner);
  if (sessionHasPermission_(session, 'tasks:view')) {
    if (assigneeEmail === sessionEmail || assignerEmail === sessionEmail) {
      return true;
    }
    if (assigneeEmail && canManageUser_(session, assigneeEmail, usersMap)) {
      return true;
    }
    if (assignerEmail && canManageUser_(session, assignerEmail, usersMap)) {
      return true;
    }
  }
  if (sessionHasPermission_(session, 'tasks:view:self') || sessionHasPermission_(session, 'tasks:manage:self')) {
    if (assigneeEmail === sessionEmail || assignerEmail === sessionEmail) {
      return true;
    }
  }
  return false;
}

function normalizeTaskFilters_(filters) {
  if (!filters) {
    filters = {};
  } else if (typeof filters === 'string') {
    filters = safeParse_(filters, {});
  }
  if (!filters || typeof filters !== 'object') {
    filters = {};
  }
  var normalized = {};
  var limit = Number(filters.limit);
  if (!limit || limit <= 0) {
    limit = 50;
  }
  normalized.limit = Math.min(Math.floor(limit), 200);
  if (normalized.limit <= 0) {
    normalized.limit = 50;
  }
  var cursor = Number(filters.cursor);
  if (!cursor || cursor < 0) {
    cursor = 0;
  }
  normalized.cursor = Math.floor(cursor);
  normalized.statuses = normalizeToLowerArray_(pickFirstDefined_(filters, ['status', 'statuses']));
  normalized.categories = normalizeToLowerArray_(pickFirstDefined_(filters, ['category', 'categories']));
  normalized.priorities = normalizeToLowerArray_(pickFirstDefined_(filters, ['priority', 'priorities']));
  normalized.assignee = normalizeEmail_(pickFirstDefined_(filters, ['assignee', 'Assignee']));
  normalized.assigner = normalizeEmail_(pickFirstDefined_(filters, ['assigner', 'Assigner']));
  normalized.parentTaskId = pickFirstDefined_(filters, ['parentTaskId', 'ParentTaskID', 'parentId', 'ParentID']) || '';
  var searchValue = pickFirstDefined_(filters, ['search', 'Search']);
  normalized.search = searchValue ? String(searchValue).trim().toLowerCase() : '';
  normalized.dueAfter = parseDateValue_(pickFirstDefined_(filters, ['dueAfter', 'DueAfter']));
  normalized.dueBefore = parseDateValue_(pickFirstDefined_(filters, ['dueBefore', 'DueBefore']));
  return normalized;
}

function normalizeToLowerArray_(value) {
  var list = [];
  if (value === undefined || value === null) {
    return list;
  }
  var source;
  if (Array.isArray(value)) {
    source = value;
  } else {
    source = String(value).split(',');
  }
  for (var i = 0; i < source.length; i++) {
    var item = source[i];
    if (item === undefined || item === null) {
      continue;
    }
    var trimmed = String(item).trim();
    if (trimmed) {
      list.push(trimmed.toLowerCase());
    }
  }
  return list;
}

function parseDateValue_(value) {
  if (!value) {
    return null;
  }
  if (Object.prototype.toString.call(value) === '[object Date]') {
    if (!isNaN(value.getTime())) {
      return value;
    }
    return null;
  }
  var date = new Date(value);
  if (!isNaN(date.getTime())) {
    return date;
  }
  if (typeof value === 'number') {
    var fromNumber = new Date(Number(value));
    if (!isNaN(fromNumber.getTime())) {
      return fromNumber;
    }
  }
  return null;
}

function taskMatchesFilters_(taskRecord, filters) {
  if (filters.statuses.length && filters.statuses.indexOf(String(taskRecord.Status || '').toLowerCase()) === -1) {
    return false;
  }
  if (filters.categories.length && filters.categories.indexOf(String(taskRecord.Category || '').toLowerCase()) === -1) {
    return false;
  }
  if (filters.priorities.length && filters.priorities.indexOf(String(taskRecord.Priority || '').toLowerCase()) === -1) {
    return false;
  }
  if (filters.assignee && normalizeEmail_(taskRecord.Assignee) !== filters.assignee) {
    return false;
  }
  if (filters.assigner && normalizeEmail_(taskRecord.Assigner) !== filters.assigner) {
    return false;
  }
  if (filters.parentTaskId && String(taskRecord.ParentTaskID || '') !== String(filters.parentTaskId)) {
    return false;
  }
  if (filters.search) {
    var haystack = [
      taskRecord.Name || '',
      taskRecord.Notes || '',
      taskRecord.Labels || '',
      taskRecord.Category || '',
      taskRecord.Priority || ''
    ].join(' ').toLowerCase();
    if (haystack.indexOf(filters.search) === -1) {
      return false;
    }
  }
  if (filters.dueAfter || filters.dueBefore) {
    var dueDate = parseDateValue_(taskRecord.DueAt);
    if (!dueDate) {
      if (filters.dueAfter || filters.dueBefore) {
        return false;
      }
    } else {
      if (filters.dueAfter && dueDate.getTime() < filters.dueAfter.getTime()) {
        return false;
      }
      if (filters.dueBefore && dueDate.getTime() > filters.dueBefore.getTime()) {
        return false;
      }
    }
  }
  return true;
}

function toCsvString_(value) {
  if (value === undefined || value === null) {
    return '';
  }
  if (Array.isArray(value)) {
    var cleaned = [];
    for (var i = 0; i < value.length; i++) {
      var entry = value[i];
      if (entry === undefined || entry === null) {
        continue;
      }
      var trimmed = String(entry).trim();
      if (trimmed) {
        cleaned.push(trimmed);
      }
    }
    return cleaned.join(', ');
  }
  return String(value);
}

function parseLabels_(value) {
  if (value === undefined || value === null || value === '') {
    return [];
  }
  if (Array.isArray(value)) {
    var fromArray = [];
    for (var i = 0; i < value.length; i++) {
      if (value[i] === undefined || value[i] === null) {
        continue;
      }
      var trimmed = String(value[i]).trim();
      if (trimmed) {
        fromArray.push(trimmed);
      }
    }
    return fromArray;
  }
  var parts = String(value).split(',');
  var list = [];
  for (var j = 0; j < parts.length; j++) {
    var part = parts[j].trim();
    if (part) {
      list.push(part);
    }
  }
  return list;
}

function normalizeDuration_(value, fallback) {
  if (value === undefined || value === null || value === '') {
    var fallbackNumber = Number(fallback);
    return isNaN(fallbackNumber) ? 0 : Math.max(0, fallbackNumber);
  }
  var num = Number(value);
  if (isNaN(num)) {
    var fallbackNum = Number(fallback);
    return isNaN(fallbackNum) ? 0 : Math.max(0, fallbackNum);
  }
  if (num < 0) {
    return 0;
  }
  return Math.round(num * 100) / 100;
}

function normalizeStatus_(status) {
  var candidate = status !== undefined && status !== null ? String(status).trim() : '';
  if (!candidate) {
    return 'Planned';
  }
  var lower = candidate.toLowerCase();
  for (var i = 0; i < TASK_STATUSES.length; i++) {
    if (TASK_STATUSES[i].toLowerCase() === lower) {
      return TASK_STATUSES[i];
    }
  }
  throw new Error('Invalid status.');
}

function sanitizeTask_(record) {
  if (!record) {
    return null;
  }
  return {
    TaskID: record.TaskID,
    Name: record.Name || '',
    Category: record.Category || '',
    Priority: record.Priority || '',
    Status: record.Status || 'Planned',
    DurationMins: normalizeDuration_(record.DurationMins, 0),
    Labels: parseLabels_(record.Labels),
    Notes: record.Notes || '',
    ResourcesCSV: record.ResourcesCSV || '',
    Resources: parseLabels_(record.ResourcesCSV),
    Assigner: record.Assigner || '',
    Assignee: record.Assignee || '',
    Timestamp: record.Timestamp || '',
    DueAt: record.DueAt || '',
    UpdatedAt: record.UpdatedAt || '',
    ParentTaskID: record.ParentTaskID || ''
  };
}

function sanitizeSubtask_(record) {
  if (!record) {
    return null;
  }
  return {
    SubtaskID: record.SubtaskID,
    TaskID: record.TaskID,
    Name: record.Name || '',
    DurationMins: normalizeDuration_(record.DurationMins, 0),
    Status: record.Status || 'Planned',
    CreatedAt: record.CreatedAt || ''
  };
}

function sanitizeMood_(record) {
  if (!record) {
    return null;
  }
  return {
    EntryID: record.EntryID,
    TaskID: record.TaskID || '',
    Email: record.Email || '',
    Mood: record.Mood || '',
    Note: record.Note || '',
    At: record.At || ''
  };
}

function getTaskById_(taskId) {
  if (!taskId) {
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
  var searchId = String(taskId);
  for (var i = 0; i < values.length; i++) {
    if (String(values[i][idIndex]) === searchId) {
      return {
        rowNumber: i + 2,
        record: arrayToObject_(headers, values[i])
      };
    }
  }
  return null;
}

function getSubtaskById_(subtaskId) {
  if (!subtaskId) {
    return null;
  }
  var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.SUBTASKS];
  var idIndex = headers.indexOf('SubtaskID');
  if (idIndex === -1) {
    throw new Error('Subtasks sheet missing SubtaskID column.');
  }
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return null;
  }
  var range = sheet.getRange(2, 1, lastRow - 1, headers.length);
  var values = range.getValues();
  var searchId = String(subtaskId);
  for (var i = 0; i < values.length; i++) {
    if (String(values[i][idIndex]) === searchId) {
      return {
        rowNumber: i + 2,
        record: arrayToObject_(headers, values[i])
      };
    }
  }
  return null;
}

function getSubtasksForTask_(taskId) {
  var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.SUBTASKS];
  var rows = sheetObjects_(sheet, headers);
  if (!taskId) {
    return rows;
  }
  var searchId = String(taskId);
  var results = [];
  for (var i = 0; i < rows.length; i++) {
    if (String(rows[i].TaskID || '') === searchId) {
      results.push(rows[i]);
    }
  }
  return results;
}

function deleteSubtasksForTask_(taskId) {
  if (!taskId) {
    return;
  }
  var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
  var headers = SHEET_HEADERS[SHEET_NAMES.SUBTASKS];
  var idIndex = headers.indexOf('TaskID');
  if (idIndex === -1) {
    return;
  }
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return;
  }
  var range = sheet.getRange(2, 1, lastRow - 1, headers.length);
  var values = range.getValues();
  var searchId = String(taskId);
  for (var i = values.length - 1; i >= 0; i--) {
    if (String(values[i][idIndex]) === searchId) {
      sheet.deleteRow(i + 2);
    }
  }
}
