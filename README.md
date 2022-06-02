# ntbclient

Note to generate the debian package !

## Package generation

### Install tools to build package :
```
apt install git git-buildpackage dpkg-dev devscripts equivs
```

### If you want use ntb in intramfs, you should satisfy it and create a stand-alone binary with pyinstaller :
```
apt install python3-pip
pip install pyinstaller
```

### Copy repository :
```
git clone https://forge.greyc.fr/git/ntbclient
cd ntbclient
```

### If you want to make some modification.
#### Make your modification :
```
vi ...
```

#### Add and commit your personal modification :
```
git add .
git commit
```

#### Increase the version ( by adding "-1" for example ) :
```
vi debian/control
```

#### Ðefine your email :
```
export DEBEMAIL="noreply@example.com"
```

#### Get version and print it for verification :
```
VERSION=`grep "Standards-Version:" debian/control | cut -f2 -d" "` ; echo $VERSION
```

#### Generate changelog ( edit as you want and save) :
```
gbp dch --ignore-branch --id-length=8 -R -N ${VERSION}
```
#### ( Share your modification !? ;) )

### Install dependencies for the generation :
```
mk-build-deps --install
```

### Generate the package :
```
dpkg-buildpackage
```

### Get the package :
```
ls -al ..
```
