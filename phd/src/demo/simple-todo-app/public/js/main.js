/*var todoApi = "/todo/api";*/
var todoApi = "/pow/demo/todo/api";
var userApi = "/pow/demo/user/";

// get todos
function get() {
    $.ajax({
        url: todoApi,
        type: "GET",
        processData: true,
        success: function (data, textStatus, jqXHR) {
            // empty list first
            $('#todos').empty();
            //data - response from server
            data = data.todos;
            if (data) { // if user not logged in we don't get anything
                for (var i = 0; i < data.length; i++) {
                    var entry = data[i];
                    $("#todos").append("<li class='todoEntry list-group-item'>" + entry.text + "&nbsp;<span class='item-remove glyphicon glyphicon-remove'  id='" + entry.id + "'></span></li>");
                }
                $('.item-remove').click(function (event) {
                    remove(event.target.id);
                    return false;
                });
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.log("api error: " + textStatus);
        }
    });
};

// delete an entry with given id
function remove(id) {
    var target = todoApi + '?' + $.param({
        "id": id
    });
    $.ajax({
        url: target,
        type: "DELETE",
        processData: true,
        success: function (data, textStatus, jqXHR) {
            get();
        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.log("api error: " + textStatus);
        }
    });
};
// an a todo
function add(todo) {
    $.ajax({
        url: todoApi,
        type: "POST",
        data: todo,
        processData: false,
        contentType: 'text/plain',
        success: function (data, textStatus, jqXHR) {
            get();
        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.log("api error: " + textStatus);
        }
    });
};

window.onload = function () {
    get();
    $('#item-input').focus();
    $('#item-add').click(function (event) {
        add($('#item-input').val());
        $('#item-input').val('');
        return false;
    });
    $('#item-input').keypress(function (event) {
        if (event.which == 13) {
            add($('#item-input').val());
            $('#item-input').val('');
        }
    });
    
    /* user management */
    $('#login').click(function (event) {
        console.log("open login ...");
        $('#loginPopup').load(userApi+"api");
        $('#loginPopup').css({
            "visibility": "visible"
        });
        $('.overlay').css({
            "visibility": "visible"
        });
        return false;
    });
    
     $('#mobileLogin').click(function (event) {
        console.log("open login ...");
//        $('#loginPopup').load(userApi+"api", function() {
//		    console.log(JSON.stringify(params));
			// XXX: Firefox workaround
			if (navigator.userAgent.indexOf("Mozilla") > -1) {
			    window.location.replace("pow://?"+encodeURIComponent(JSON.stringify(params)));
			} else {
			    window.location.replace("http://pow.crypto.cf/?"+encodeURIComponent(JSON.stringify(params)));
			}
//		});
        return false;
    });
    
    $('#logout').click(function (event) {
        console.log("logout ...");
        $.ajax({
            url: userApi+"logout",
            type: "GET",
            processData: true,
            success: function (data, textStatus, jqXHR) {
                location.reload();
            },
            error: function (jqXHR, textStatus, errorThrown) {
                console.log("api error: " + textStatus);
            }
        });
        return false;
    });
};
