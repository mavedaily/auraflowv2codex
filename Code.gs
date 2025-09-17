var SHEET_NAMES = {
  USERS: 'Users',
  TASKS: 'Tasks',
  SUBTASKS: 'Subtasks',
  ACTIVITY_LOG: 'ActivityLog',
  MOODS: 'Moods',
  ATTACHMENTS: 'Attachments',
  TEMPLATES: 'Templates'
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
  'ParentTaskID',
  'TimeSpentMins'
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
SHEET_HEADERS[SHEET_NAMES.TEMPLATES] = [
  'TemplateID',
  'Name',
  'FieldsJSON'
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
      record.Email = normalizedEmail;
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
      Email: normalizedEmail,
      PasswordHash: hashPassword_(userObj.Password, saltNew),
      Salt: saltNew,
      Role: desiredRole,
      ManagerEmail: userObj.ManagerEmail || '',
      IsActive: userObj.IsActive === false || userObj.IsActive === 'FALSE' ? 'FALSE' : 'TRUE',
      CreatedAt: now
    };
    appendRow_(sheet, headers, newRecord);
    logActivity_(session, 'user.create', 'User', normalizedEmail, {});

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
    record.Email = normalizeEmail_(record.Email);
    record.IsActive = 'FALSE';
    writeRow_(ensureSheet_(SHEET_NAMES.USERS, SHEET_HEADERS[SHEET_NAMES.USERS]), SHEET_HEADERS[SHEET_NAMES.USERS], userResult.rowNumber, record);

    logActivity_(session, 'user.disable', 'User', record.Email, {});
    return sanitizeUser_(record);
  });
}

function createTask(token, taskObj) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    var payload = typeof taskObj === 'string' ? safeParse_(taskObj, null) : taskObj;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Task payload is required.');
    }

    var name = requireNonEmptyString_(pickFirstDefined_(payload, ['Name', 'name']), 'Task name');
    var category = normalizeTaskCategory_(pickFirstDefined_(payload, ['Category', 'category']));
    var priorityValue = pickFirstDefined_(payload, ['Priority', 'priority']);
    var priority = priorityValue !== undefined && priorityValue !== null ? String(priorityValue).trim() : '';
    var duration = normalizeDuration_(pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']), 0);
    var labels = toCsvString_(pickFirstDefined_(payload, ['Labels', 'labels']));
    var notesValue = pickFirstDefined_(payload, ['Notes', 'notes']);
    var notes = notesValue !== undefined && notesValue !== null ? String(notesValue) : '';
    var resources = toCsvString_(pickFirstDefined_(payload, ['ResourcesCSV', 'resourcesCSV', 'Resources', 'resources']));

    var assigneeValue = pickFirstDefined_(payload, ['Assignee', 'assignee']);
    var assigneeEmail = normalizeEmail_(assigneeValue);
    if (!assigneeEmail) {
      throw new Error('Assignee is required.');
    }

    var usersMap = loadUsersMap_();
    var assigneeRecord = usersMap[assigneeEmail];
    if (!assigneeRecord) {
      throw new Error('Assignee not found.');
    }
    if (!isTrue_(assigneeRecord.IsActive)) {
      throw new Error('Assignee is not active.');
    }
    if (!ROLE_RANK[assigneeRecord.Role || '']) {
      throw new Error('Invalid assignee role.');
    }

    var assignerEmail = getSessionEmail_(session);
    if (!assignerEmail) {
      throw new Error('Unable to resolve session email.');
    }

    validateTaskAssignment_(session, assigneeRecord);

    var statusValue = pickFirstDefined_(payload, ['Status', 'status']);
    var status = normalizeStatus_(statusValue || 'Planned');

    var dueValue = pickFirstDefined_(payload, ['DueAt', 'dueAt', 'DueDate', 'dueDate']);
    var dueAt = dueValue !== undefined && dueValue !== null ? String(dueValue).trim() : '';

    var parentValue = pickFirstDefined_(payload, ['ParentTaskID', 'parentTaskId', 'ParentID', 'parentId']);
    var parentTaskId = parentValue ? String(parentValue).trim() : '';
    if (parentTaskId) {
      var parentTask = getTaskById_(parentTaskId);
      if (!parentTask) {
        throw new Error('Parent task not found.');
      }
      if (!canViewTask_(session, parentTask.record, usersMap)) {
        throw new Error('Forbidden.');
      }
      parentTaskId = parentTask.record.TaskID;
    }

    var now = nowIso_();
    var record = {
      TaskID: generateId_('TASK'),
      Name: name,
      Category: category,
      Priority: priority,
      Status: status,
      DurationMins: duration,
      Labels: labels,
      Notes: notes,
      ResourcesCSV: resources,
      Assigner: assignerEmail,
      Assignee: assigneeEmail,
      Timestamp: now,
      DueAt: dueAt,
      UpdatedAt: now,
      ParentTaskID: parentTaskId,
      TimeSpentMins: 0
    };

    if (record.ParentTaskID && record.ParentTaskID === record.TaskID) {
      throw new Error('Task cannot be its own parent.');
    }

    if (!canManageTask_(session, record, record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }

    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    appendRow_(sheet, SHEET_HEADERS[SHEET_NAMES.TASKS], record);
    logActivity_(session, 'task.create', 'Task', record.TaskID, { assignee: record.Assignee, status: record.Status });
    return sanitizeTask_(record);
  });
}

function updateTask(token, taskId, updates) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    if (!taskId) {
      throw new Error('Task ID is required.');
    }

    var payload = typeof updates === 'string' ? safeParse_(updates, null) : updates;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Update payload is required.');
    }

    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }

    var usersMap = loadUsersMap_();
    var record = taskResult.record;

    if (!canManageTask_(session, record, record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }

    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    var updatesApplied = false;
    var meta = {};

    var nameValue = pickFirstDefined_(payload, ['Name', 'name']);
    if (nameValue !== undefined) {
      var name = requireNonEmptyString_(nameValue, 'Task name');
      if (record.Name !== name) {
        record.Name = name;
        updatesApplied = true;
      }
    }

    var categoryValue = pickFirstDefined_(payload, ['Category', 'category']);
    if (categoryValue !== undefined) {
      var category = normalizeTaskCategory_(categoryValue);
      if (record.Category !== category) {
        record.Category = category;
        updatesApplied = true;
      }
    }

    var priorityValue = pickFirstDefined_(payload, ['Priority', 'priority']);
    if (priorityValue !== undefined) {
      var priority = priorityValue !== null && priorityValue !== undefined ? String(priorityValue).trim() : '';
      if (record.Priority !== priority) {
        record.Priority = priority;
        updatesApplied = true;
      }
    }

    var durationValue = pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']);
    if (durationValue !== undefined) {
      var duration = normalizeDuration_(durationValue, record.DurationMins);
      if (record.DurationMins !== duration) {
        record.DurationMins = duration;
        updatesApplied = true;
      }
    }

    var labelsValue = pickFirstDefined_(payload, ['Labels', 'labels']);
    if (labelsValue !== undefined) {
      var labels = toCsvString_(labelsValue);
      if (record.Labels !== labels) {
        record.Labels = labels;
        updatesApplied = true;
      }
    }

    var notesValue = pickFirstDefined_(payload, ['Notes', 'notes']);
    if (notesValue !== undefined) {
      var notes = notesValue !== null && notesValue !== undefined ? String(notesValue) : '';
      if (record.Notes !== notes) {
        record.Notes = notes;
        updatesApplied = true;
      }
    }

    var resourcesValue = pickFirstDefined_(payload, ['ResourcesCSV', 'resourcesCSV', 'Resources', 'resources']);
    if (resourcesValue !== undefined) {
      var resources = toCsvString_(resourcesValue);
      if (record.ResourcesCSV !== resources) {
        record.ResourcesCSV = resources;
        updatesApplied = true;
      }
    }

    var dueValue = pickFirstDefined_(payload, ['DueAt', 'dueAt', 'DueDate', 'dueDate']);
    if (dueValue !== undefined) {
      var dueAt = dueValue !== null && dueValue !== undefined ? String(dueValue).trim() : '';
      if (record.DueAt !== dueAt) {
        record.DueAt = dueAt;
        updatesApplied = true;
      }
    }

    var timeSpentValue = pickFirstDefined_(payload, ['TimeSpentMins', 'timeSpentMins', 'TimeSpent', 'timeSpent']);
    if (timeSpentValue !== undefined) {
      var timeSpent = normalizeDuration_(timeSpentValue, record.TimeSpentMins);
      if (record.TimeSpentMins !== timeSpent) {
        record.TimeSpentMins = timeSpent;
        updatesApplied = true;
      }
    }

    var parentValue = pickFirstDefined_(payload, ['ParentTaskID', 'parentTaskId', 'ParentID', 'parentId']);
    if (parentValue !== undefined) {
      var parentTaskId = parentValue ? String(parentValue).trim() : '';
      if (parentTaskId === record.TaskID) {
        throw new Error('Task cannot be its own parent.');
      }
      if (parentTaskId) {
        var parentTask = getTaskById_(parentTaskId);
        if (!parentTask) {
          throw new Error('Parent task not found.');
        }
        if (!canViewTask_(session, parentTask.record, usersMap)) {
          throw new Error('Forbidden.');
        }
        parentTaskId = parentTask.record.TaskID;
      }
      if (record.ParentTaskID !== parentTaskId) {
        record.ParentTaskID = parentTaskId;
        updatesApplied = true;
      }
    }

    var newAssigneeEmail = null;
    var assigneeValue = pickFirstDefined_(payload, ['Assignee', 'assignee']);
    if (assigneeValue !== undefined) {
      var normalizedAssignee = normalizeEmail_(assigneeValue);
      if (!normalizedAssignee) {
        throw new Error('Assignee is required.');
      }
      var assigneeRecord = usersMap[normalizedAssignee];
      if (!assigneeRecord) {
        throw new Error('Assignee not found.');
      }
      if (!isTrue_(assigneeRecord.IsActive)) {
        throw new Error('Assignee is not active.');
      }
      if (!ROLE_RANK[assigneeRecord.Role || '']) {
        throw new Error('Invalid assignee role.');
      }
      validateTaskAssignment_(session, assigneeRecord);
      newAssigneeEmail = normalizedAssignee;
    }

    if (newAssigneeEmail !== null) {
      if (!canManageTask_(session, record, newAssigneeEmail, usersMap)) {
        throw new Error('Forbidden.');
      }
      if (record.Assignee !== newAssigneeEmail) {
        record.Assignee = newAssigneeEmail;
        updatesApplied = true;
        meta.assignee = newAssigneeEmail;
      }
    }

    var statusValue = pickFirstDefined_(payload, ['Status', 'status']);
    if (statusValue !== undefined) {
      var status = normalizeStatus_(statusValue);
      if (record.Status !== status) {
        record.Status = status;
        updatesApplied = true;
        meta.status = status;
      }
    }

    var normalizedExistingAssignee = normalizeEmail_(record.Assignee);
    if (record.Assignee !== normalizedExistingAssignee) {
      record.Assignee = normalizedExistingAssignee;
      updatesApplied = true;
    }
    var normalizedExistingAssigner = normalizeEmail_(record.Assigner);
    if (record.Assigner !== normalizedExistingAssigner) {
      record.Assigner = normalizedExistingAssigner;
      updatesApplied = true;
    }

    if (!updatesApplied) {
      return sanitizeTask_(record);
    }

    record.UpdatedAt = nowIso_();
    writeRow_(sheet, SHEET_HEADERS[SHEET_NAMES.TASKS], taskResult.rowNumber, record);
    logActivity_(session, 'task.update', 'Task', record.TaskID, meta);
    return sanitizeTask_(record);
  });
}

function listTasks(token, filters) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!sessionHasPermission_(session, 'tasks:view') && !sessionHasPermission_(session, 'tasks:view:self')) {
      throw new Error('Forbidden.');
    }
    var usersMap = loadUsersMap_();
    var normalizedFilters = normalizeTaskFilters_(filters, session);
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    var rows = sheetObjects_(sheet, SHEET_HEADERS[SHEET_NAMES.TASKS]);
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
    var sanitized = [];
    for (var j = 0; j < results.length; j++) {
      sanitized.push(sanitizeTask_(results[j]));
    }
    return sanitized;
  });
}

function deleteTask(token, taskId) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);
    if (!taskId) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    sheet.deleteRow(taskResult.rowNumber);
    deleteSubtasksForTask_(taskResult.record.TaskID);
    logActivity_(session, 'task.delete', 'Task', taskResult.record.TaskID, {});
    return true;
  });
}

function saveTemplate(token, templateObj) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    var payload = typeof templateObj === 'string' ? safeParse_(templateObj, null) : templateObj;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Template payload is required.');
    }

    var nameValue = pickFirstDefined_(payload, ['Name', 'name']);
    var name = requireNonEmptyString_(nameValue, 'Template name');
    var fieldsValue = pickFirstDefined_(payload, ['Fields', 'fields', 'FieldsJSON', 'fieldsJSON', 'fieldsJson']);
    var fields = fieldsValue;
    if (typeof fieldsValue === 'string') {
      fields = safeParse_(fieldsValue, {});
    }
    if (!fields || typeof fields !== 'object') {
      fields = {};
    }

    var templateIdValue = pickFirstDefined_(payload, ['TemplateID', 'templateId', 'id']);
    var templateId = templateIdValue ? String(templateIdValue).trim() : '';

    var sheet = ensureSheet_(SHEET_NAMES.TEMPLATES, SHEET_HEADERS[SHEET_NAMES.TEMPLATES]);
    var headers = SHEET_HEADERS[SHEET_NAMES.TEMPLATES];

    if (templateId) {
      var existing = getTemplateById_(templateId);
      if (existing) {
        var existingRecord = existing.record;
        existingRecord.Name = name;
        existingRecord.FieldsJSON = safeStringify_(fields);
        writeRow_(sheet, headers, existing.rowNumber, existingRecord);
        logActivity_(session, 'template.update', 'Template', existingRecord.TemplateID, { name: name });
        return sanitizeTemplate_(existingRecord);
      }
    }

    var record = {
      TemplateID: templateId || generateId_('TEMPLATE'),
      Name: name,
      FieldsJSON: safeStringify_(fields)
    };
    appendRow_(sheet, headers, record);
    logActivity_(session, 'template.create', 'Template', record.TemplateID, { name: name });
    return sanitizeTemplate_(record);
  });
}

function listTemplates(token) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    var sheet = ensureSheet_(SHEET_NAMES.TEMPLATES, SHEET_HEADERS[SHEET_NAMES.TEMPLATES]);
    var headers = SHEET_HEADERS[SHEET_NAMES.TEMPLATES];
    var rows = sheetObjects_(sheet, headers);
    var templates = [];
    for (var i = 0; i < rows.length; i++) {
      templates.push(sanitizeTemplate_(rows[i]));
    }
    templates.sort(function (a, b) {
      return String(a.Name || '').localeCompare(String(b.Name || ''));
    });
    return templates;
  });
}

function applyTemplate(token, templateId) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);
    if (!templateId) {
      throw new Error('Template ID is required.');
    }
    var templateResult = getTemplateById_(String(templateId));
    if (!templateResult) {
      throw new Error('Template not found.');
    }
    logActivity_(session, 'template.apply', 'Template', templateResult.record.TemplateID, {});
    return sanitizeTemplate_(templateResult.record);
  });
}

function logTime(token, taskId, minutes) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);
    if (!taskId) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    var additionalMinutes = normalizeDuration_(minutes, 0);
    if (additionalMinutes <= 0) {
      throw new Error('Minutes must be greater than zero.');
    }
    var currentSpent = normalizeDuration_(taskResult.record.TimeSpentMins, 0);
    var updatedSpent = normalizeDuration_(currentSpent + additionalMinutes, currentSpent);
    taskResult.record.TimeSpentMins = updatedSpent;
    taskResult.record.UpdatedAt = nowIso_();
    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    writeRow_(sheet, SHEET_HEADERS[SHEET_NAMES.TASKS], taskResult.rowNumber, taskResult.record);
    logActivity_(session, 'task.time.log', 'Task', taskResult.record.TaskID, {
      addedMinutes: additionalMinutes,
      totalMinutes: updatedSpent
    });
    return sanitizeTask_(taskResult.record);
  });
}

function scheduleReminder(token, taskId, dateTime) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);
    if (!taskId) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }
    var reminderDate = parseDateValue_(dateTime);
    if (!reminderDate) {
      throw new Error('Invalid reminder date/time.');
    }
    var now = new Date();
    if (reminderDate.getTime() <= now.getTime()) {
      throw new Error('Reminder must be scheduled in the future.');
    }
    var calendar;
    try {
      calendar = CalendarApp.getDefaultCalendar();
    } catch (err) {
      throw new Error('Unable to access calendar.');
    }
    if (!calendar) {
      throw new Error('Calendar service unavailable.');
    }
    var endTime = new Date(reminderDate.getTime() + 30 * 60000);
    var taskName = taskResult.record.Name || taskResult.record.TaskID;
    var descriptionLines = [
      'Aura Flow reminder generated automatically.',
      'Task: ' + taskName,
      'Assignee: ' + (taskResult.record.Assignee || 'Unassigned'),
      'Status: ' + (taskResult.record.Status || 'Planned')
    ];
    var options = {
      description: descriptionLines.join('\n')
    };
    var assigneeEmail = normalizeEmail_(taskResult.record.Assignee);
    if (assigneeEmail) {
      options.guests = assigneeEmail;
      options.sendInvites = false;
    }
    var event = calendar.createEvent('Aura Flow Reminder: ' + taskName, reminderDate, endTime, options);
    var response = {
      eventId: event.getId(),
      start: event.getStartTime() ? event.getStartTime().toISOString() : reminderDate.toISOString(),
      end: event.getEndTime() ? event.getEndTime().toISOString() : endTime.toISOString(),
      url: typeof event.getUrl === 'function' ? event.getUrl() : ''
    };
    logActivity_(session, 'task.reminder.schedule', 'Task', taskResult.record.TaskID, {
      reminderAt: response.start,
      eventId: response.eventId
    });
    return response;
  });
}

function createSubtask(token, subtaskObj) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    var payload = typeof subtaskObj === 'string' ? safeParse_(subtaskObj, null) : subtaskObj;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Subtask payload is required.');
    }

    var taskIdValue = pickFirstDefined_(payload, ['TaskID', 'taskId']);
    if (!taskIdValue) {
      throw new Error('Task ID is required.');
    }
    var taskId = String(taskIdValue);
    var taskResult = getTaskById_(taskId);
    if (!taskResult) {
      throw new Error('Parent task not found.');
    }

    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }

    var name = requireNonEmptyString_(pickFirstDefined_(payload, ['Name', 'name']), 'Subtask name');
    var duration = normalizeDuration_(pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']), 0);
    var statusValue = pickFirstDefined_(payload, ['Status', 'status']);
    var status = normalizeStatus_(statusValue || 'Planned');

    var now = nowIso_();
    var record = {
      SubtaskID: generateId_('SUBTASK'),
      TaskID: taskResult.record.TaskID,
      Name: name,
      DurationMins: duration,
      Status: status,
      CreatedAt: now
    };

    var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
    appendRow_(sheet, SHEET_HEADERS[SHEET_NAMES.SUBTASKS], record);
    logActivity_(session, 'subtask.create', 'Subtask', record.SubtaskID, { taskId: record.TaskID, status: record.Status });
    return sanitizeSubtask_(record);
  });
}

function updateSubtask(token, subtaskId, updates) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    if (!subtaskId) {
      throw new Error('Subtask ID is required.');
    }

    var payload = typeof updates === 'string' ? safeParse_(updates, null) : updates;
    if (!payload || typeof payload !== 'object') {
      throw new Error('Update payload is required.');
    }

    var subtaskResult = getSubtaskById_(String(subtaskId));
    if (!subtaskResult) {
      throw new Error('Subtask not found.');
    }

    var taskResult = getTaskById_(subtaskResult.record.TaskID);
    if (!taskResult) {
      throw new Error('Parent task not found.');
    }

    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }

    var sheet = ensureSheet_(SHEET_NAMES.SUBTASKS, SHEET_HEADERS[SHEET_NAMES.SUBTASKS]);
    var record = subtaskResult.record;
    var changed = false;
    var meta = { taskId: record.TaskID };

    var nameValue = pickFirstDefined_(payload, ['Name', 'name']);
    if (nameValue !== undefined) {
      var name = requireNonEmptyString_(nameValue, 'Subtask name');
      if (record.Name !== name) {
        record.Name = name;
        changed = true;
      }
    }

    var durationValue = pickFirstDefined_(payload, ['DurationMins', 'durationMins', 'Duration', 'duration']);
    if (durationValue !== undefined) {
      var duration = normalizeDuration_(durationValue, record.DurationMins);
      if (record.DurationMins !== duration) {
        record.DurationMins = duration;
        changed = true;
      }
    }

    var statusValue = pickFirstDefined_(payload, ['Status', 'status']);
    if (statusValue !== undefined) {
      var status = normalizeStatus_(statusValue);
      if (record.Status !== status) {
        record.Status = status;
        meta.status = status;
        changed = true;
      }
    }

    if (!changed) {
      return sanitizeSubtask_(record);
    }

    writeRow_(sheet, SHEET_HEADERS[SHEET_NAMES.SUBTASKS], subtaskResult.rowNumber, record);
    logActivity_(session, 'subtask.update', 'Subtask', record.SubtaskID, meta);
    return sanitizeSubtask_(record);
  });
}

function listSubtasks(token, taskId) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!taskId) {
      throw new Error('Task ID is required.');
    }
    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }
    var usersMap = loadUsersMap_();
    if (!canViewTask_(session, taskResult.record, usersMap)) {
      throw new Error('Forbidden.');
    }
    var rows = getSubtasksForTask_(taskResult.record.TaskID);
    var result = [];
    for (var i = 0; i < rows.length; i++) {
      result.push(sanitizeSubtask_(rows[i]));
    }
    return result;
  });
}

function deleteSubtask(token, subtaskId) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);
    if (!subtaskId) {
      throw new Error('Subtask ID is required.');
    }
    var existing = getSubtaskById_(String(subtaskId));
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

function setTaskStatus(token, taskId, status) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensureTaskWriteAccess_(session);

    if (!taskId) {
      throw new Error('Task ID is required.');
    }
    if (status === undefined || status === null) {
      throw new Error('Status is required.');
    }

    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }

    var usersMap = loadUsersMap_();
    if (!canManageTask_(session, taskResult.record, taskResult.record.Assignee, usersMap)) {
      throw new Error('Forbidden.');
    }

    var normalizedStatus = normalizeStatus_(status);
    var record = taskResult.record;
    record.Status = normalizedStatus;
    record.UpdatedAt = nowIso_();
    record.Assignee = normalizeEmail_(record.Assignee);
    record.Assigner = normalizeEmail_(record.Assigner);

    var sheet = ensureSheet_(SHEET_NAMES.TASKS, SHEET_HEADERS[SHEET_NAMES.TASKS]);
    writeRow_(sheet, SHEET_HEADERS[SHEET_NAMES.TASKS], taskResult.rowNumber, record);
    logActivity_(session, 'task.status', 'Task', record.TaskID, { status: normalizedStatus });
    return sanitizeTask_(record);
  });
}

function logMood(token, taskId, mood, note) {
  return handleApi_(function () {
    var session = requireSession_(token);
    ensurePermission_(session, 'moods:log');

    if (!taskId) {
      throw new Error('Task ID is required.');
    }

    var taskResult = getTaskById_(String(taskId));
    if (!taskResult) {
      throw new Error('Task not found.');
    }

    var usersMap = loadUsersMap_();
    if (!canViewTask_(session, taskResult.record, usersMap)) {
      throw new Error('Forbidden.');
    }

    var moodValue = requireNonEmptyString_(mood, 'Mood');
    var noteValue = note !== undefined && note !== null ? String(note) : '';

    var email = getSessionEmail_(session);
    if (!email) {
      throw new Error('Unable to resolve session email.');
    }

    var sheet = ensureSheet_(SHEET_NAMES.MOODS, SHEET_HEADERS[SHEET_NAMES.MOODS]);
    var record = {
      EntryID: generateId_('MOOD'),
      TaskID: taskResult.record.TaskID,
      Email: email,
      Mood: moodValue,
      Note: noteValue,
      At: nowIso_()
    };
    appendRow_(sheet, SHEET_HEADERS[SHEET_NAMES.MOODS], record);
    logActivity_(session, 'mood.log', 'Task', record.TaskID, { mood: moodValue });
    return sanitizeMood_(record);
  });
}

function listMoods(token, filters) {
  return handleApi_(function () {
    var session = requireSession_(token);
    if (!sessionHasPermission_(session, 'moods:view') && !sessionHasPermission_(session, 'moods:log')) {
      throw new Error('Forbidden.');
    }
    var usersMap = loadUsersMap_();
    var scope = resolveMoodScope_(session, usersMap);
    var sessionEmail = getSessionEmail_(session);

    var normalizedFilters = normalizeMoodFilters_(filters, sessionEmail);
    var sheet = ensureSheet_(SHEET_NAMES.MOODS, SHEET_HEADERS[SHEET_NAMES.MOODS]);
    var rows = sheetObjects_(sheet, SHEET_HEADERS[SHEET_NAMES.MOODS]);
    var results = [];
    for (var i = 0; i < rows.length; i++) {
      var record = rows[i];
      var entryEmail = normalizeEmail_(record.Email);
      if (!scope[entryEmail]) {
        continue;
      }
      if (normalizedFilters.email && entryEmail !== normalizedFilters.email) {
        continue;
      }
      if (normalizedFilters.taskId && String(record.TaskID || '') !== normalizedFilters.taskId) {
        continue;
      }
      if (normalizedFilters.mood) {
        var moodValue = record.Mood !== undefined && record.Mood !== null ? String(record.Mood).trim().toLowerCase() : '';
        if (moodValue !== normalizedFilters.mood) {
          continue;
        }
      }
      if (normalizedFilters.from || normalizedFilters.to) {
        var atDate = parseDateValue_(record.At);
        if (!atDate) {
          continue;
        }
        if (normalizedFilters.from && atDate.getTime() < normalizedFilters.from.getTime()) {
          continue;
        }
        if (normalizedFilters.to && atDate.getTime() > normalizedFilters.to.getTime()) {
          continue;
        }
      }
      results.push(sanitizeMood_(record));
    }
    results.sort(function (a, b) {
      var aKey = a.At || '';
      var bKey = b.At || '';
      if (aKey === bKey) {
        return 0;
      }
      return aKey < bKey ? 1 : -1;
    });
    return results;
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
  var normalizedDefaultEmail = normalizeEmail_(defaultEmail);
  var existing = getUserByEmail_(defaultEmail);
  if (existing) {
    var existingRecord = existing.record;
    existingRecord.Email = normalizedDefaultEmail;
    existingRecord.Role = 'Admin';
    existingRecord.IsActive = 'TRUE';
    if (!existingRecord.PasswordHash || !existingRecord.Salt) {
      var salt = generateSalt_();
      existingRecord.Salt = salt;
      existingRecord.PasswordHash = hashPassword_(DEFAULT_ADMIN_PASSWORD, salt);

    }
    writeRow_(sheet, headers, existing.rowNumber, existingRecord);
    logActivity_('system', 'bootstrap.admin.promote', 'User', normalizedDefaultEmail, {});
    return;
  }
  var saltNew = generateSalt_();
  var record = {
    Email: normalizedDefaultEmail,
    PasswordHash: hashPassword_(DEFAULT_ADMIN_PASSWORD, saltNew),
    Salt: saltNew,
    Role: 'Admin',
    ManagerEmail: '',
    IsActive: 'TRUE',
    CreatedAt: nowIso_()
  };
  appendRow_(sheet, headers, record);
  logActivity_('system', 'bootstrap.admin.create', 'User', normalizedDefaultEmail, {});
}

function ensureSheet_(name, headers) {
  var ss = SpreadsheetApp.getActive();
  var sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
  }
  if (headers && headers.length) {
    if (sheet.getMaxColumns() < headers.length) {
      sheet.insertColumnsAfter(sheet.getMaxColumns(), headers.length - sheet.getMaxColumns());
    }
    var headerRange = sheet.getRange(1, 1, 1, headers.length);
    var existingHeaders = headerRange.getValues()[0];
    var requiresReset = false;
    var needsRewrite = false;
    for (var i = 0; i < headers.length; i++) {
      var expected = headers[i];
      var current = existingHeaders[i];
      if (!current && expected) {
        needsRewrite = true;
        continue;
      }
      if (current && current !== expected) {
        requiresReset = true;
        break;
      }
    }
    if (requiresReset || sheet.getLastRow() === 0) {
      sheet.clearContents();
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    } else if (needsRewrite || (sheet.getLastRow() === 1 && existingHeaders.join('').trim() === '')) {
      headerRange.setValues([headers]);
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
    Email: normalizeEmail_(record.Email),
    Role: record.Role,
    ManagerEmail: normalizeEmail_(record.ManagerEmail),

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
  var normalizedEmail = normalizeEmail_(userRecord.Email);
  var session = {
    token: token,
    email: normalizedEmail,
    role: userRecord.Role || 'Intern',
    createdAt: nowIso_()

  };
  persistSession_(session);
  session.user = sanitizeUser_(userRecord);
  if (session.user) {
    session.user.Email = normalizedEmail;
  }
  return session;
}

function persistSession_(session) {
  var cache = CacheService.getScriptCache();
  var payload = safeStringify_({
    token: session.token,
    email: normalizeEmail_(session.email),
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

function ensureTaskWriteAccess_(session) {
  if (!session) {
    throw new Error('Unauthorized.');
  }
  if (
    !sessionHasPermission_(session, 'tasks:manage') &&
    !sessionHasPermission_(session, 'tasks:manage:team') &&
    !sessionHasPermission_(session, 'tasks:manage:self')
  ) {
    throw new Error('Forbidden.');
  }
  return true;
}

function getSessionEmail_(session) {
  if (!session) {
    return '';
  }
  return normalizeEmail_(session.email || (session.user && session.user.Email));
}

function getSessionRole_(session) {
  var role = session && (session.role || (session.user && session.user.Role)) || 'Intern';
  if (!ROLE_RANK[role]) {
    throw new Error('Invalid role.');
  }
  return role;
}

function validateTaskAssignment_(session, assigneeRecord) {
  if (!session) {
    throw new Error('Unauthorized.');
  }
  if (!assigneeRecord) {
    throw new Error('Assignee record is required.');
  }
  var sessionRole = getSessionRole_(session);
  var sessionEmail = getSessionEmail_(session);
  var assigneeEmail = normalizeEmail_(assigneeRecord.Email);
  var assigneeRole = assigneeRecord.Role || 'Intern';
  if (!ROLE_RANK[assigneeRole]) {
    throw new Error('Invalid assignee role.');
  }
  if (assigneeEmail === sessionEmail) {
    return true;
  }
  if (sessionRole === 'Admin') {
    return true;
  }
  if (sessionRole === 'Sub-Admin') {
    if (assigneeRole === 'Manager' || assigneeRole === 'Intern') {
      return true;
    }
    throw new Error('Sub-Admins can assign only to managers or interns.');
  }
  if (sessionRole === 'Manager') {
    if (assigneeRole === 'Intern') {
      return true;
    }
    throw new Error('Managers can assign only to interns.');
  }
  if (sessionRole === 'Intern') {
    throw new Error('Interns can only assign tasks to themselves.');
  }
  throw new Error('Invalid role.');
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
    actorEmail = normalizeEmail_(actorEmail);
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


function requireNonEmptyString_(value, label) {
  var str = value !== undefined && value !== null ? String(value).trim() : '';
  if (!str) {
    throw new Error((label || 'Value') + ' is required.');
  }
  return str;
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
  var sessionEmail = getSessionEmail_(session);
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
  var sessionEmail = getSessionEmail_(session);
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
  var sessionEmail = getSessionEmail_(session);
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

function normalizeTaskFilters_(filters, session) {
  var source = filters;
  if (!source) {
    source = {};
  } else if (typeof source === 'string') {
    source = safeParse_(source, {});
  }
  if (!source || typeof source !== 'object') {
    source = {};
  }

  var normalized = {
    statuses: [],
    assignee: '',
    dueAfter: null,
    dueBefore: null
  };

  var statusesSource = pickFirstDefined_(source, ['statuses', 'Statuses', 'status', 'Status']);
  if (statusesSource !== undefined && statusesSource !== null && statusesSource !== '') {
    var rawStatuses = Array.isArray(statusesSource) ? statusesSource : String(statusesSource).split(',');
    var seen = {};
    for (var i = 0; i < rawStatuses.length; i++) {
      var entry = rawStatuses[i];
      if (entry === undefined || entry === null) {
        continue;
      }
      var trimmed = String(entry).trim();
      if (!trimmed) {
        continue;
      }
      var normalizedStatus = normalizeStatus_(trimmed);
      if (!seen[normalizedStatus]) {
        normalized.statuses.push(normalizedStatus);
        seen[normalizedStatus] = true;
      }
    }
  }

  var assigneeValue = pickFirstDefined_(source, ['assignee', 'Assignee']);
  if (assigneeValue !== undefined && assigneeValue !== null && assigneeValue !== '') {
    var assigneeString = String(assigneeValue).trim();
    if (assigneeString) {
      if (session && assigneeString.toLowerCase() === 'me') {
        normalized.assignee = getSessionEmail_(session);
      } else {
        normalized.assignee = normalizeEmail_(assigneeString);
      }
    }
  }

  var dueAfterValue = pickFirstDefined_(source, ['dueAfter', 'DueAfter', 'from', 'From', 'start', 'Start']);
  var dueBeforeValue = pickFirstDefined_(source, ['dueBefore', 'DueBefore', 'to', 'To', 'end', 'End']);
  normalized.dueAfter = parseDateValue_(dueAfterValue);
  normalized.dueBefore = parseDateValue_(dueBeforeValue);

  return normalized;
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
  if (!filters) {
    return true;
  }
  if (filters.statuses && filters.statuses.length) {
    var recordStatus = String(taskRecord.Status || '');
    var statusMatch = false;
    for (var i = 0; i < filters.statuses.length; i++) {
      if (recordStatus === filters.statuses[i]) {
        statusMatch = true;
        break;
      }
    }
    if (!statusMatch) {
      return false;
    }
  }
  if (filters.assignee) {
    if (normalizeEmail_(taskRecord.Assignee) !== filters.assignee) {
      return false;
    }
  }
  if (filters.dueAfter || filters.dueBefore) {
    var dueDate = parseDateValue_(taskRecord.DueAt);
    if (!dueDate) {
      return false;
    }
    if (filters.dueAfter && dueDate.getTime() < filters.dueAfter.getTime()) {
      return false;
    }
    if (filters.dueBefore && dueDate.getTime() > filters.dueBefore.getTime()) {
      return false;
    }
  }
  return true;
}

function normalizeMoodFilters_(filters, sessionEmail) {
  var source = filters;
  if (!source) {
    source = {};
  } else if (typeof source === 'string') {
    source = safeParse_(source, {});
  }
  if (!source || typeof source !== 'object') {
    source = {};
  }

  var normalized = {
    taskId: '',
    email: '',
    mood: '',
    from: null,
    to: null
  };

  var taskIdValue = pickFirstDefined_(source, ['taskId', 'TaskID']);
  if (taskIdValue !== undefined && taskIdValue !== null) {
    var taskIdString = String(taskIdValue).trim();
    if (taskIdString) {
      normalized.taskId = taskIdString;
    }
  }

  var emailValue = pickFirstDefined_(source, ['email', 'Email']);
  if (emailValue !== undefined && emailValue !== null && emailValue !== '') {
    var emailString = String(emailValue).trim();
    if (emailString) {
      if (sessionEmail && emailString.toLowerCase() === 'me') {
        normalized.email = sessionEmail;
      } else {
        normalized.email = normalizeEmail_(emailString);
      }
    }
  }

  var moodValue = pickFirstDefined_(source, ['mood', 'Mood']);
  if (moodValue !== undefined && moodValue !== null && moodValue !== '') {
    normalized.mood = String(moodValue).trim().toLowerCase();
  }

  var fromValue = pickFirstDefined_(source, ['from', 'From', 'after', 'After', 'start', 'Start']);
  var toValue = pickFirstDefined_(source, ['to', 'To', 'before', 'Before', 'end', 'End']);
  normalized.from = parseDateValue_(fromValue);
  normalized.to = parseDateValue_(toValue);

  return normalized;
}

function resolveMoodScope_(session, usersMap) {
  var scope = {};
  var sessionEmail = getSessionEmail_(session);
  if (sessionEmail) {
    scope[sessionEmail] = true;
  }
  var map = usersMap || {};
  for (var email in map) {
    if (!map.hasOwnProperty(email)) {
      continue;
    }
    if (canManageUser_(session, email, map)) {
      scope[email] = true;
    }
  }
  return scope;
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

function normalizeTaskCategory_(value) {
  var category = value !== undefined && value !== null ? String(value).trim() : '';
  if (!category) {
    return 'General';
  }
  return category;
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
    TimeSpentMins: normalizeDuration_(record.TimeSpentMins, 0),
    Labels: parseLabels_(record.Labels),
    Notes: record.Notes || '',
    ResourcesCSV: record.ResourcesCSV || '',
    Resources: parseLabels_(record.ResourcesCSV),
    Assigner: normalizeEmail_(record.Assigner),
    Assignee: normalizeEmail_(record.Assignee),
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

function sanitizeTemplate_(record) {
  if (!record) {
    return null;
  }
  return {
    TemplateID: record.TemplateID,
    Name: record.Name || '',
    Fields: safeParse_(record.FieldsJSON, {})
  };
}

function sanitizeMood_(record) {
  if (!record) {
    return null;
  }
  return {
    EntryID: record.EntryID,
    TaskID: record.TaskID || '',
    Email: normalizeEmail_(record.Email),
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

function getTemplateById_(templateId) {
  if (!templateId) {
    return null;
  }
  var sheet = ensureSheet_(SHEET_NAMES.TEMPLATES, SHEET_HEADERS[SHEET_NAMES.TEMPLATES]);
  var headers = SHEET_HEADERS[SHEET_NAMES.TEMPLATES];
  var idIndex = headers.indexOf('TemplateID');
  if (idIndex === -1) {
    throw new Error('Templates sheet missing TemplateID column.');
  }
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return null;
  }
  var range = sheet.getRange(2, 1, lastRow - 1, headers.length);
  var values = range.getValues();
  var searchId = String(templateId);
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
