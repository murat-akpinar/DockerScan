import React, { createContext, useContext, useState } from 'react';
import translations, { Lang, Translations } from './translations';

type LanguageContextType = {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: Translations;
};

const LanguageContext = createContext<LanguageContextType>({
  lang: 'tr',
  setLang: () => {},
  t: translations.tr,
});

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [lang, setLangState] = useState<Lang>(() => {
    const saved = localStorage.getItem('dockscan-lang');
    return saved === 'en' ? 'en' : 'tr';
  });

  const setLang = (newLang: Lang) => {
    localStorage.setItem('dockscan-lang', newLang);
    setLangState(newLang);
  };

  return (
    <LanguageContext.Provider value={{ lang, setLang, t: translations[lang] }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = () => useContext(LanguageContext);

export const LangToggle: React.FC = () => {
  const { lang, setLang } = useLanguage();
  return (
    <div className="flex items-center text-xs font-medium border border-catppuccin-surface1 rounded overflow-hidden">
      <button
        onClick={() => setLang('tr')}
        className={`px-2 py-1 transition-colors ${
          lang === 'tr'
            ? 'bg-catppuccin-teal text-catppuccin-base'
            : 'text-catppuccin-overlay1 hover:bg-catppuccin-surface0'
        }`}
      >
        TR
      </button>
      <button
        onClick={() => setLang('en')}
        className={`px-2 py-1 transition-colors ${
          lang === 'en'
            ? 'bg-catppuccin-teal text-catppuccin-base'
            : 'text-catppuccin-overlay1 hover:bg-catppuccin-surface0'
        }`}
      >
        EN
      </button>
    </div>
  );
};
