from fabric.api import *
import dnstk

@task
def tag():
    local('git tag {}'.format(dnstk.__version__))

@task
def push():
    local('git push origin {}'.format(dnstk.__version__))

@task
def upload():
    local('python3 setup.py sdist register upload')

@task
def release():
    tag()
    push()
    upload()

