from setuptools import setup, find_packages

setup(
    name='cryptocore',
    version='1.0.0',

    # 1. Указываем ВСЕ пакеты явно
    packages=[
        'cryptocore',
        'cryptocore.crypto',
        'cryptocore.crypto.modes',
        'cryptocore.hash',
        'cryptocore.kdf',
        'cryptocore.mac',
        'cryptocore.utils',
    ],

    # 2. Или используем find_packages с указанием корня
    # packages=find_packages(where='.'),
    # package_dir={'': '.'},  # Корень - текущая директория

    # 3. Указываем где искать пакеты
    package_dir={
        'cryptocore': 'src',
        'cryptocore.crypto': 'src/crypto',
        'cryptocore.crypto.modes': 'src/crypto/modes',
        'cryptocore.hash': 'src/hash',
        'cryptocore.kdf': 'src/kdf',
        'cryptocore.mac': 'src/mac',
        'cryptocore.utils': 'src/utils',
    },

    entry_points={
        'console_scripts': [
            'cryptocore=cryptocore:main',
        ],
    },
    install_requires=[
        'pycryptodome>=3.10.1',
    ],
    python_requires='>=3.6',
)