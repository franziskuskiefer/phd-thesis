
$(document).ready(function() {

	$('#regex').keyup(function() {
	  var val = $.trim(this.value);
		$.ajax({
				type: "POST",
				url: "/changePolicy",
				data: JSON.stringify({ R: val }),
				contentType: "application/json; charset=utf-8",
				dataType: "json",
		});
	});
	
	$('#minlength').change(function() {
	  var val = $.trim(this.value);
		$.ajax({
				type: "POST",
				url: "/changePolicy",
				data: JSON.stringify({ min: val }),
				contentType: "application/json; charset=utf-8",
				dataType: "json",
		});
	});
	
	$('#openClient').click(function() {
		window.location.href = "/client";
	});

//	// save policy form
//	$('#policyForm').submit(function (event){
//		var formData = $('#policyForm').serialize();
//		$.post( 'http://localhost:8080/setPolicy', formData );
////		event.preventDefault();
//        return true;
//	});
	
//	// register new user
//	$('#registerUser').submit(function (event){
//		var formData = $('#registerUser').serialize();
//		// FIXME: check passwords and perform client side computations
////		alert(formData);
//		$.post( 'http://localhost:8080/registerUser', formData );
////		event.preventDefault();
//        return true;
//	});
	
//	$('#testButton').click(function() {
//		w = new Worker('static/js/test.js');
//		
//		// send server arguments to worker
//		params = $("#24920b44-3a8b-486b-a3f9-8f359bd1fbb2").text().trim();
//		params = $.parseJSON(params);
//		w.postMessage({ "args": params });
//		
//		// wait for first client message
//		w.onmessage = function (event) {
//        	console.log("done: " + event.data );
//		};
//	});
	
});

