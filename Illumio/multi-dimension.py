query_string = "location:aws,app:web"
label_dimensions = query_string.split(",")

for label in label_dimensions:
    key,value = label.split(":")
    print(key,value)


# params={“key”: key, “value”: value}