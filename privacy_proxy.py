"""
Alias module per ``pProxy``.

Lo strumento è distribuito come ``pProxy.py`` (vedi README e usage.txt), ma il
nome di import "canonico" usato dalla suite di test e da eventuale codice di
terze parti è ``privacy_proxy``. Questo modulo rende i due nomi intercambiabili::

    import privacy_proxy                 # equivalente a import pProxy
    from privacy_proxy import PrivacyProxy

L'aliasing avviene sostituendo questo modulo con quello reale in
``sys.modules``: dopo l'assegnazione, sia ``import privacy_proxy`` sia
``from privacy_proxy import X`` risolvono direttamente contro :mod:`pProxy`.
In questo modo le classi sono lo *stesso* oggetto a prescindere dal nome usato
(``isinstance`` e i confronti di identità restano coerenti) e non c'è alcuna
duplicazione dell'API da mantenere allineata.
"""

from __future__ import annotations

import sys as _sys

import pProxy as _pProxy

_sys.modules[__name__] = _pProxy
