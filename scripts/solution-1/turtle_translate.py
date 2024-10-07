import turtle
import re

def parse_line(line, turtle_obj):
    forward_value = re.match(r"Avance (\d+) spaces", line)
    backward_value = re.match(r"Recule (\d+) spaces", line)
    left_value = re.match(r"Tourne gauche de (\d+) degrees", line)
    right_value = re.match(r"Tourne droite de (\d+) degrees", line)

    if forward_value:
        value = int(forward_value.group(1))
        turtle_obj.forward(value)
    elif backward_value:
        value = int(backward_value.group(1))
        turtle_obj.backward(value)
    elif left_value:
        value = int(left_value.group(1))
        turtle_obj.left(value)
    elif right_value:
        value = int(right_value.group(1))
        turtle_obj.right(value)

def parse_file_to_turtle():
    screen = turtle.Screen()
    screen.setup(1000, 1000)
    t = turtle.Turtle()

    with open('turtle', 'r') as f:
        content = f.readlines()

    for line in content:
        parse_line(line, t)

    turtle.done()

parse_file_to_turtle()
