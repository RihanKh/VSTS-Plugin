del *.vsix
#tsc
tfx extension create --bypass-validation --manifest-globs vss-extension.json
#tfx extension publish --share-with Checkmarx --token x6msals6q6s7joqejd3od63xadccjfa374p5br7moorlmlhgwyra
echo | pause
