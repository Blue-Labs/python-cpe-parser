# Maintainer: David Ford <david@blue-labs.org>
pkgname=python-cpe-parser
pkgver=1.0
pkgrel=1
pkgdesc="Parse the CPE tree of an NVD vulnerability (http://web.nvd.nist.gov/)
into an object"
arch=('any')
url="https://github.com/FirefighterBlu3/python-cpe-parser"
license=('MIT')
depends=('python','python-beautifulsoup4','libxml2','libxslt')
optdepends=('python-lxml: pythonic binding for the libxml2 and libxslt libraries'
            'python-httplib2: vastly improved HTTP client library')
options=(!emptydirs)
changelog=('ChangeLog')
source=(https://pypi.python.org/packages/source/p/${pkgname}/${pkgname}-${pkgver}.tar.gz
        https://pypi.python.org/packages/source/p/${pkgname}/${pkgname}-${pkgver}.tar.gz.asc)
md5sums=(
         )

package() {
  cd "$srcdir/$pkgname-$pkgver"
  python setup.py install --root="$pkgdir/" --optimize=1
}

# vim:set ts=2 sw=2 et:
