from setuptools import find_packages, setup

install_requires = [
        "Django>=5.0.6",
    ],
setup(
    name="django_password_policies_kminc",
    version='0.8.7',
    description="A Django application to implement password policies.",
    long_description="""\
django-password-policies is an application for the Django framework that
provides unicode-aware password policies on password changes and resets
and a mechanism to force password changes.
""",
    author="Maulik Chauhan",
    author_email="maulik.chauhan00@gmail.com",
    url="https://github.com/maulik-chauhan/django-password-policies-kminc",
    include_package_data=True,
    packages=find_packages(),
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Django",
        "License :: OSI Approved :: BSD License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Utilities",
    ],
    install_requires=install_requires,
)
