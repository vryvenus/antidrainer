// Переводы: t("key", подстановки...) — {1}, {2} в тексте сообщения. Элементы с data-i18n заполняются автоматически.
export const t = (key, ...args) =>
  (chrome.i18n.getMessage(key) || key).replace(/\{(\d)\}/g, (_, i) => args[i - 1] ?? "");
// язык форматирования дат и чисел = язык, на котором показан интерфейс
export const uiLang = () => chrome.i18n.getMessage("locale") || "en";
export function applyI18n(root = document) {
  document.documentElement.lang = uiLang();
  for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll("[data-i18n-title]")) el.title = t(el.dataset.i18nTitle);
}
