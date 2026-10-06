import { apiRequest, currentSession, onAuthChange, signIn, signOut } from './auth-client.js';

const signedOut = document.querySelector('#signed-out');
const signedIn = document.querySelector('#signed-in');
const workspace = document.querySelector('#workspace');
const loginForm = document.querySelector('#login-form');
const logoutButton = document.querySelector('#logout');
const loginStatus = document.querySelector('#login-status');
const workspaceStatus = document.querySelector('#workspace-status');
const notesRoot = document.querySelector('#notes');
const createForm = document.querySelector('#create-form');

const setStatus = (element, message = '', error = false) => {
  element.textContent = message;
  element.classList.toggle('error', error);
};

const apiError = async (response, fallback) => {
  try {
    const data = await response.json();
    return typeof data?.error === 'string' ? data.error : fallback;
  } catch {
    return fallback;
  }
};

const renderAuth = session => {
  const loggedIn = Boolean(session);
  signedOut.hidden = loggedIn;
  signedIn.hidden = !loggedIn;
  workspace.hidden = !loggedIn;
  if (!loggedIn) {
    notesRoot.replaceChildren();
    setStatus(workspaceStatus);
  }
};

const noteEditor = note => {
  const article = document.createElement('article');
  article.className = 'note';

  const grid = document.createElement('div');
  grid.className = 'note-grid';

  const titleLabel = document.createElement('label');
  titleLabel.textContent = '제목';
  const title = document.createElement('input');
  title.maxLength = 120;
  title.value = note.title;
  titleLabel.append(title);

  const bodyLabel = document.createElement('label');
  bodyLabel.textContent = '본문';
  const body = document.createElement('textarea');
  body.maxLength = 2000;
  body.value = note.body;
  bodyLabel.append(body);

  const actions = document.createElement('div');
  actions.className = 'note-actions';

  const save = document.createElement('button');
  save.type = 'button';
  save.className = 'secondary';
  save.textContent = '수정 저장';

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'danger';
  remove.textContent = '삭제';

  actions.append(save, remove);
  grid.append(titleLabel, bodyLabel, actions);
  article.append(grid);

  save.addEventListener('click', async () => {
    setStatus(workspaceStatus, '수정 중…');
    try {
      const response = await apiRequest(`/api/notes/${encodeURIComponent(note.id)}`, {
        method: 'PUT',
        body: JSON.stringify({ title: title.value, body: body.value }),
      });
      if (!response.ok) {
        setStatus(workspaceStatus, await apiError(response, '수정에 실패했습니다.'), true);
        return;
      }
      setStatus(workspaceStatus, '수정했습니다.');
      await loadNotes();
    } catch (error) {
      setStatus(workspaceStatus, error.message, true);
    }
  });

  remove.addEventListener('click', async () => {
    if (!window.confirm('이 가상 메모를 삭제할까요?')) return;
    setStatus(workspaceStatus, '삭제 중…');
    try {
      const response = await apiRequest(`/api/notes/${encodeURIComponent(note.id)}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        setStatus(workspaceStatus, await apiError(response, '삭제에 실패했습니다.'), true);
        return;
      }
      setStatus(workspaceStatus, '삭제했습니다.');
      await loadNotes();
    } catch (error) {
      setStatus(workspaceStatus, error.message, true);
    }
  });

  return article;
};

async function loadNotes() {
  try {
    const response = await apiRequest('/api/notes');
    if (!response.ok) {
      setStatus(workspaceStatus, await apiError(response, '자료를 읽을 수 없습니다.'), true);
      notesRoot.replaceChildren();
      return;
    }

    const notes = await response.json();
    if (!Array.isArray(notes)) {
      setStatus(workspaceStatus, '자료 형식이 맞지 않습니다.', true);
      return;
    }

    notesRoot.replaceChildren(...notes.map(noteEditor));
    setStatus(workspaceStatus, notes.length ? '' : '내 메모가 없습니다. 새 메모를 추가해 보세요.');
  } catch (error) {
    notesRoot.replaceChildren();
    setStatus(workspaceStatus, error.message, true);
  }
}

loginForm.addEventListener('submit', async event => {
  event.preventDefault();
  setStatus(loginStatus, '로그인 중…');

  const email = document.querySelector('#email').value.trim();
  const password = document.querySelector('#password').value;
  const { data, error } = await signIn(email, password);

  if (error) {
    setStatus(loginStatus, error.message, true);
    return;
  }

  document.querySelector('#password').value = '';
  setStatus(loginStatus);
  renderAuth(data.session);
  await loadNotes();
});

logoutButton.addEventListener('click', async () => {
  const { error } = await signOut();
  if (error) {
    setStatus(workspaceStatus, error.message, true);
    return;
  }
  renderAuth(null);
});

createForm.addEventListener('submit', async event => {
  event.preventDefault();

  const title = document.querySelector('#new-title');
  const body = document.querySelector('#new-body');
  setStatus(workspaceStatus, '추가 중…');

  try {
    const response = await apiRequest('/api/notes', {
      method: 'POST',
      body: JSON.stringify({ title: title.value, body: body.value }),
    });

    if (!response.ok) {
      setStatus(workspaceStatus, await apiError(response, '추가에 실패했습니다.'), true);
      return;
    }

    title.value = '';
    body.value = '';
    setStatus(workspaceStatus, '추가했습니다.');
    await loadNotes();
  } catch (error) {
    setStatus(workspaceStatus, error.message, true);
  }
});

onAuthChange(session => {
  renderAuth(session);
  if (session) void loadNotes();
});

const initial = await currentSession();
if (initial.error) setStatus(loginStatus, initial.error.message, true);
renderAuth(initial.session);
if (initial.session) await loadNotes();
