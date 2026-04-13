import { useEffect, useRef, useState } from 'react';
import '../../styles/Navbar.css';

const BellIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M12 3a5 5 0 0 0-5 5v2.3c0 .8-.3 1.6-.9 2.2L4.8 14a1 1 0 0 0 .7 1.7h13a1 1 0 0 0 .7-1.7l-1.3-1.5c-.6-.6-.9-1.4-.9-2.2V8a5 5 0 0 0-5-5Zm0 18a2.8 2.8 0 0 0 2.7-2h-5.4A2.8 2.8 0 0 0 12 21Z" />
  </svg>
);

const UserIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M12 12a4.5 4.5 0 1 0-4.5-4.5A4.5 4.5 0 0 0 12 12Zm0 2.2c-4 0-7.2 2.3-7.2 5.1a1 1 0 0 0 1 1h12.4a1 1 0 0 0 1-1c0-2.8-3.2-5.1-7.2-5.1Z" />
  </svg>
);

const MenuIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M4 7h16a1 1 0 0 0 0-2H4a1 1 0 0 0 0 2Zm16 4H4a1 1 0 0 0 0 2h16a1 1 0 0 0 0-2Zm0 6H4a1 1 0 0 0 0 2h16a1 1 0 0 0 0-2Z" />
  </svg>
);

const SearchIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M15.9 14.5a7 7 0 1 0-1.4 1.4l4.6 4.6a1 1 0 0 0 1.4-1.4l-4.6-4.6ZM5 10a5 5 0 1 1 5 5 5 5 0 0 1-5-5Z" />
  </svg>
);

function Navbar() {
  const [search, setSearch] = useState('');
  const [isVisible, setIsVisible] = useState(false);
  const hideTimerRef = useRef(null);

  const clearHideTimer = () => {
    if (hideTimerRef.current) {
      clearTimeout(hideTimerRef.current);
      hideTimerRef.current = null;
    }
  };

  const showNavbar = () => {
    clearHideTimer();
    setIsVisible(true);
  };

  const hideNavbarWithDelay = () => {
    clearHideTimer();
    hideTimerRef.current = setTimeout(() => {
      setIsVisible(false);
      hideTimerRef.current = null;
    }, 140);
  };

  useEffect(() => () => clearHideTimer(), []);

  return (
    <div className="navbar-shell" aria-hidden={false}>
      <div
        className="navbar-hover-zone"
        onMouseEnter={showNavbar}
        aria-hidden="true"
      />

      <header
        className={`navbar ${isVisible ? 'visible' : 'hidden'}`}
        role="banner"
        onMouseEnter={showNavbar}
        onMouseLeave={hideNavbarWithDelay}
      >
        <div className="navbar__aurora" aria-hidden="true" />

        <div className="navbar__left">
          <div className="navbar__logo-mark" aria-hidden="true">N</div>
          <div>
            <p className="navbar__logo">NETCOM GROUPE</p>
            <p className="navbar__tagline">MikroTik Operations Center</p>
          </div>
        </div>

        <div className="navbar__center">
          <label className="navbar__search-wrapper" htmlFor="global-search">
            <span className="navbar__search-icon"><SearchIcon /></span>
            <input
              id="global-search"
              className="navbar__search-input"
              type="search"
              placeholder="Search ticket, IP, client..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search"
            />
            <kbd className="navbar__shortcut">⌘K</kbd>
          </label>
        </div>

        <nav className="navbar__right" aria-label="Quick actions">
          <button className="navbar__icon-btn" type="button" aria-label="Notifications">
            <BellIcon />
            <span className="navbar__dot" aria-hidden="true" />
          </button>

          <button className="navbar__icon-btn" type="button" aria-label="Profile">
            <UserIcon />
          </button>

          <button className="navbar__icon-btn" type="button" aria-label="Menu">
            <MenuIcon />
          </button>
        </nav>
      </header>
    </div>
  );
}

export default Navbar;