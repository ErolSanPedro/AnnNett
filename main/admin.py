from django.contrib import admin

# Register your models here.

# from main.models import Blacklist, Audit

# admin.site.register(Blacklist)
# admin.site.register(Audit)


# from main.models import Author, Nationality, Genre, Book, BookInstance

# ##admin.site.register(Book)
# admin.site.register(Nationality)
# ## admin.site.register(Author)
# admin.site.register(Genre)
# ##admin.site.register(BookInstance)


# # Define the admin class
# class AuthorAdmin(admin.ModelAdmin):
# 	list_display = ('last_name', 'first_name', 'nationality', 'date_of_birth', 'date_of_death')
# 	fields = ['first_name', 'last_name', 'nationality', ('date_of_birth', 'date_of_death')]

# # Register the admin class with the associated model
# admin.site.register(Author, AuthorAdmin)

# class BooksInstanceInline(admin.TabularInline):
#     model = BookInstance

# # Register the Admin classes for Book using the decorator
# @admin.register(Book)
# class BookAdmin(admin.ModelAdmin):
# 	list_display = ('title', 'author', 'display_genre')
# 	inlines = [BooksInstanceInline]

# # Register the Admin classes for BookInstance using the decorator
# @admin.register(BookInstance) 
# class BookInstanceAdmin(admin.ModelAdmin):
# 	list_filter = ('status', 'due_back')
	
# 	fieldsets = (
#         (None, {
#             'fields': ('book', 'imprint', 'id')
#         }),
#         ('Availability', {
#             'fields': ('status', 'due_back')
#         }),
#     )
		
