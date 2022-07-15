---
layout: default
title: "embe221ed"
permalink: /
---
Posts:

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> ({{ post.tags | join: ", " }})
          <blockquote>{{ post.excerpt }}</blockquote>
    </li>
  {% endfor %}
</ul>
