const { pathname, hostname, href } = window.location;

if (pathname.startsWith('/z')) {
  window.location.href = href.replace('/z', '/a');
}

if (
  (hostname === 'mkfun.github.io') && !localStorage.getItem('tt-global-state')
) {
  window.location.href = 'https://mktgweb.pooziqo.xyz';
}
