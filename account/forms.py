from django import forms
import re
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm

from account.models import User


class EmployeeRegistrationForm(UserCreationForm):


    def __init__(self, *args, **kwargs):
        UserCreationForm.__init__(self, *args, **kwargs)
        self.fields['first_name'].required = True
        self.fields['last_name'].required = True
        self.fields['email'].required = True
        self.fields['password1'].required = True
        self.fields['password2'].required = True
        self.fields['MobileNumber'].required = True
        self.fields['gender'].required = True
        self.fields['linkdin'].required = True

        #Labels
        self.fields['first_name'].label = "First Name :"
        self.fields['last_name'].label = "Last Name :"
        self.fields['password1'].label = "Password :"
        self.fields['password2'].label = "Confirm Password :"
        self.fields['email'].label = "Email :"
        self.fields['gender'].label = "Gender :"
        self.fields['location'].label = "Location :"
        self.fields['skills'].label = "Skills :"
        self.fields['MobileNumber'].label = "Mobile Number :"
        self.fields['Xth'].label = "X th :"
        self.fields['XIIth'].label = "XII th :"
        self.fields['UG'].label = "Under Graduate :"
        self.fields['PG'].label = "Post Graduate :"
        self.fields['Experience'].label = "Experience :"
        self.fields['AcademicProjects'].label = "Academic Projects :"
        self.fields['linkdin'].label = "Linkdin Account :"
        self.fields['Github'].label = "Github Account :"
        self.fields['category'].label = "Category :"
        self.fields['subcategory'].label = "Subcategory :"
        self.fields['image'].label = "Profile Image :"

# Placeholders
        placeholders = {
            'first_name': 'Enter First Name',
            'last_name': 'Enter Last Name',
            'email': 'Enter Email',
            'password1': 'Enter Password',
            'password2': 'Confirm Password',
            'MobileNumber': 'Enter Mobile Number',
        }
        for field, placeholder in placeholders.items():
            self.fields[field].widget.attrs.update({'placeholder': placeholder})


        optional_fields = ['location', 'skills', 'Xth', 'XIIth', 'UG', 'PG', 'Experience', 'AcademicProjects', 'category', 'subcategory']
        for field in optional_fields:
            self.fields[field].required = False
            self.fields[field].widget.attrs.update({'placeholder': ''})

        # Add placeholder for LinkedIn field
        self.fields['linkdin'].widget.attrs.update({'placeholder': 'Enter LinkedIn Profile URL'})

    class Meta:

        model=User

        fields = ['first_name', 'last_name', 'gender', 'email', 'password1', 'password2','location', 'skills', 'MobileNumber', 'Xth', 'XIIth', 'UG', 'PG', 'Experience', 'AcademicProjects','linkdin','Github','category','subcategory','image']

    def clean_gender(self):
        gender = self.cleaned_data.get('gender')
        if not gender:
            raise forms.ValidationError("Gender is required")
        return gender

    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        if not re.search(r'[a-z]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        if not re.search(r'[0-9]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        return password
    
    def save(self, commit=True):
        user = UserCreationForm.save(self,commit=False)
        user.role = "employee"
        if commit:
            user.save()
        return user


class EmployerRegistrationForm(UserCreationForm):
    def __init__(self, *args, **kwargs):
        UserCreationForm.__init__(self, *args, **kwargs)
        self.fields['first_name'].required = True
        self.fields['last_name'].required = True
        self.fields['email'].required = True
        self.fields['password1'].required = True
        self.fields['password2'].required = True

        self.fields['first_name'].label = "Company Name"
        self.fields['last_name'].label = "Company Address"
        self.fields['password1'].label = "Password"
        self.fields['password2'].label = "Confirm Password"

        self.fields['first_name'].widget.attrs.update({'placeholder': 'Enter Company Name'})
        self.fields['last_name'].widget.attrs.update({'placeholder': 'Enter Company Address'})
        self.fields['email'].widget.attrs.update({'placeholder': 'Enter Email'})
        self.fields['password1'].widget.attrs.update({'placeholder': 'Enter Password'})
        self.fields['password2'].widget.attrs.update({'placeholder': 'Confirm Password'})

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2']


    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        if not re.search(r'[a-z]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        if not re.search(r'[0-9]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise forms.ValidationError("Password must contain at least one uppercase letter, one lower case, one special character, one number.")
        return password


    def save(self, commit=True):
        user = UserCreationForm.save(self,commit=False)
        user.role = "employer"
        if commit:
            user.save()
        return user


class UserLoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'placeholder': 'Email'}))
    password = forms.CharField(strip=False, widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))

    def clean(self, *args, **kwargs):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email and password:
            self.user = authenticate(email=email, password=password)
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise forms.ValidationError("User does not exist.")
            if not user.check_password(password):
                raise forms.ValidationError("Incorrect password.")
            if not user.is_active:
                raise forms.ValidationError("User is not active.")
        return super(UserLoginForm, self).clean(*args, **kwargs)

    def get_user(self):
        return self.user


class EmployeeProfileEditForm(forms.ModelForm):
    def clean_image(self):
        image = self.cleaned_data.get('image')
        if image:
            from django.core.exceptions import ValidationError
            from PIL import Image
            import os
            # Check file extension
            ext = os.path.splitext(image.name)[1].lower()
            if ext not in ['.jpg', '.jpeg']:
                raise ValidationError("Your picture must be jpg formate and size would be 200 X 200 px.")
            # Check image size strictly
            try:
                img = Image.open(image)
                if img.format != 'JPEG':
                    raise ValidationError("Your picture must be jpg formate and size would be 200 X 200 px.")
                width, height = img.size
                if width != 200 or height != 200:
                    raise ValidationError("Your picture must be jpg formate and size would be 200 X 200 px.")
            except Exception:
                raise ValidationError("Your picture must be jpg formate and size would be 200 X 200 px.")
        return image

    def __init__(self, *args, **kwargs):
        super(EmployeeProfileEditForm, self).__init__(*args, **kwargs)

        # Required fields
        self.fields['first_name'].required = True
        self.fields['last_name'].required = True
        self.fields['MobileNumber'].required = True
        self.fields['gender'].required = True

        self.fields['first_name'].widget.attrs.update({'placeholder': 'Enter First Name'})
        self.fields['last_name'].widget.attrs.update({'placeholder': 'Enter Last Name'})
        self.fields['skills'].widget.attrs.update({'placeholder': '*************'})

        # Optional fields
        optional_fields = ['location', 'skills', 'Xth', 'XIIth', 'UG', 'PG', 'Experience', 'AcademicProjects', "linkdin","Github",'category','subcategory','image']
        for field in optional_fields:
            self.fields[field].required = False
            self.fields[field].widget.attrs.update({'placeholder': ''})

    class Meta:
        model = User
        fields = ["first_name", "last_name", "gender", "location", "skills", "MobileNumber", "Xth", "XIIth", "UG", "PG", "Experience", "AcademicProjects", "linkdin","Github",'category','subcategory','image']
